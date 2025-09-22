package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"time"

	"dmh/internal/api"
	"dmh/internal/execute"
	"dmh/internal/metric"
	"dmh/internal/state"
	"dmh/internal/vault"
)

var (
	getActionsInterval     = 5
	getActionsIntervalUnit = time.Minute
	actionProcessUnit      = time.Hour
	// mocks for tests
	stateNew   = state.New
	executeNew = execute.New
	vaultNew   = vault.New
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)

	configFile := os.Getenv("DMH_CONFIG_FILE")
	if configFile == "" {
		configFile = "config.yaml"
	}

	k := readConfig(configFile)

	enabledComponents := k.Strings("components")

	switch k.String("action.process_unit") {
	case "second":
		actionProcessUnit = time.Second
	case "minute":
		actionProcessUnit = time.Minute
	default:
		actionProcessUnit = time.Hour
	}

	if slices.Contains(enabledComponents, "dmh") && slices.Contains(enabledComponents, "vault") {
		log.Printf("dmh and vault component enabled. THIS IS NOT RECOMENDATED FOR SECURITY REASONS!")
	}

	var s state.StateInterface
	var v vault.VaultInterface
	var e execute.ExecuteInterface
	var err error
	if slices.Contains(enabledComponents, "dmh") {
		log.Printf("starting DMH component")
		s, err = stateNew(&state.Options{
			VaultURL:        k.String("remote_vault.url"),
			VaultClientUUID: k.String("remote_vault.client_uuid"),
			SavePath:        k.String("state.file"),
		})
		if err != nil {
			log.Panicf("unable to create state: %s", err)
		}

		bulkSMSConf := getBulkSMSConfig(k)
		mailConf := getMailConfig(k)

		e, err = executeNew(&execute.Options{
			BulkSMSConf: bulkSMSConf,
			MailConf:    mailConf,
		})
		if err != nil {
			log.Panicf("unable to create execute: %s", err)
		}
	}

	if slices.Contains(enabledComponents, "vault") {
		log.Printf("starting vault component")
		v, err = vaultNew(&vault.Options{
			Key:               k.String("vault.key"),
			SavePath:          k.String("vault.file"),
			SecretProcessUnit: actionProcessUnit,
		})
		if err != nil {
			log.Panicf("unable to create vault: %s", err)
		}
	}

	m := metric.Initialize(&metric.Options{State: s})

	if slices.Contains(enabledComponents, "dmh") {
		go dispatcher(s, e, m, actionProcessUnit, make(chan bool))
	}

	httpRouter := api.NewRouter(&api.Options{
		State:           s,
		Vault:           v,
		Execute:         e,
		VaultURL:        k.String("remote_vault.url"),
		VaultClientUUID: k.String("remote_vault.client_uuid"),
		DMHEnabled:      slices.Contains(enabledComponents, "dmh"),
		VaultEnabled:    slices.Contains(enabledComponents, "vault"),
	})

	http.ListenAndServe(fmt.Sprintf(":%d", api.HTTPPort), httpRouter)
}

func dispatcher(s state.StateInterface, e execute.ExecuteInterface, m *metric.PromCollector, actionProcessUnit time.Duration, chStop chan bool) {
	processActionsTicker := time.NewTicker(time.Duration(getActionsInterval) * getActionsIntervalUnit)
	for {
		select {
		case <-processActionsTicker.C:
			for _, a := range s.GetActions() {
				if a.Processed == 2 {
					continue
				}
				now := time.Now()
				if now.Sub(s.GetLastSeen()) > time.Duration(a.ProcessAfter)*actionProcessUnit {
					lastRun, err := s.GetActionLastRun(a.UUID)
					if err != nil {
						log.Printf("unable to get action last run  %s: %s", a.UUID, err)
						m.UpdateDMHActionErrors(a.UUID, "GetActionLastRun", 1)
						continue
					}
					if now.Sub(lastRun) > time.Duration(a.MinInterval)*actionProcessUnit {
						if a.Processed == 0 {
							log.Printf("running action %s (kind:%s, comment:%s)", a.UUID, a.Kind, a.Comment)
							decryptedAction, err := s.DecryptAction(a.UUID)
							if err != nil {
								log.Printf("unable to decrypt action %s: %s", a.UUID, err)
								m.UpdateDMHActionErrors(a.UUID, "DecryptAction", 1)
								continue
							}

							if err := e.Run(decryptedAction); err != nil {
								log.Printf("unable to run action %s: %s", a.UUID, err)
								m.UpdateDMHActionErrors(a.UUID, "Run", 1)
								continue
							}
							if err := s.UpdateActionLastRun(a.UUID); err != nil {
								log.Printf("unable to update action last run %s: %s", a.UUID, err)
								m.UpdateDMHActionErrors(a.UUID, "UpdateActionLastRun", 1)
								continue
							}
						}
						if a.MinInterval <= 0 {
							if err := s.MarkActionAsProcessed(a.UUID); err != nil {
								log.Printf("unable to mark action %s as processed: %s", a.UUID, err)
								m.UpdateDMHActionErrors(a.UUID, "MarkActionAsProcessed", 1)
								continue
							}
						}
					}
				}
			}
		// used only for tests
		case <-chStop:
			return
		}
	}
}
