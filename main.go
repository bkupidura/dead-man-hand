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
	processMessagesInterval     = 10
	processMessagesIntervalUnit = time.Minute
	actionProcessAfterUnit      = time.Hour
	actionMinIntervalUnit       = time.Hour
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)

	configFile := os.Getenv("DMH_CONFIG_FILE")
	if configFile == "" {
		configFile = "config.yaml"
	}

	k := readConfig(configFile)

	enabledComponents := k.Strings("components")

	if slices.Contains(enabledComponents, "dmh") && slices.Contains(enabledComponents, "vault") {
		log.Printf("dmh and vault component enabled. THIS IS NOT RECOMENDATED FOR SECURITY REASONS!")
	}

	var s state.StateInterface
	var v vault.VaultInterface
	var e execute.ExecuteInterface
	var err error
	if slices.Contains(enabledComponents, "dmh") {
		log.Printf("starting DMH component")
		s, err = state.New(&state.Options{
			VaultURL:        k.String("remote_vault.url"),
			VaultClientUUID: k.String("remote_vault.client_uuid"),
			SavePath:        k.String("state.file"),
		})
		if err != nil {
			log.Panicf("unable to create state: %s", err)
		}

		bulkSMSConf := getBulkSMSConfig(k)
		mailConf := getMailConfig(k)

		e, err = execute.New(&execute.Options{
			BulkSMSConf: bulkSMSConf,
			MailConf:    mailConf,
		})
		if err != nil {
			log.Panicf("unable to create execute: %s", err)
		}

		go dispatcher(s, e)
	}

	if slices.Contains(enabledComponents, "vault") {
		log.Printf("starting vault component")
		v, err = vault.New(&vault.Options{
			Key:      k.String("vault.key"),
			SavePath: k.String("vault.file"),
		})
		if err != nil {
			log.Panicf("unable to create vault: %s", err)
		}
	}

	metric.Initialize(&metric.Options{State: s})

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

func dispatcher(s state.StateInterface, e execute.ExecuteInterface) {
	processMessagesTicker := time.NewTicker(time.Duration(processMessagesInterval) * processMessagesIntervalUnit)
	for {
		select {
		case <-processMessagesTicker.C:
			for _, a := range s.GetActions() {
				if a.Processed == 2 {
					continue
				}
				now := time.Now()
				if now.Sub(s.GetLastSeen()) > time.Duration(a.ProcessAfter)*actionProcessAfterUnit {
					lastRun, err := s.GetActionLastRun(a.UUID)
					if err != nil {
						log.Printf("unable to get action last run  %s: %s", a.UUID, err)
						continue
					}
					if now.Sub(lastRun) > time.Duration(a.MinInterval)*actionMinIntervalUnit {
						if a.Processed == 0 {
							decryptedAction, err := s.DecryptAction(a.UUID)
							if err != nil {
								log.Printf("unable to decrypt action %s: %s", a.UUID, err)
								continue
							}
							log.Printf("running action %s (kind:%s, comment:%s)", a.UUID, a.Kind, a.Comment)
							if err := e.Run(decryptedAction); err != nil {
								log.Printf("unable to run action %s: %s", a.UUID, err)
								continue
							}
							if err := s.UpdateActionLastRun(a.UUID); err != nil {
								log.Printf("unable to update action last run %s: %s", a.UUID, err)
								continue
							}
						}
						if a.MinInterval <= 0 {
							if err := s.MarkActionAsProcessed(a.UUID); err != nil {
								log.Printf("unable to mark action %s as processed: %s", a.UUID, err)
								continue
							}
						}
					}
				}
			}
		}
	}
}
