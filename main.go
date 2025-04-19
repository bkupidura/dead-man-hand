package main

import (
	"encoding/json"
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
	processMessagesInterval     = 15
	aliveProbeInterval          = 15
	aliveProbeIntervalUnit      = time.Minute
	aliveProcessAfterUnit       = time.Hour
	aliveMinIntervalUnit        = time.Hour
	processMessagesIntervalUnit = time.Minute
	processAfterIntervalUnit    = time.Hour
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

		alive := getAliveConfig(k)

		go dispatcher(s, e, alive)
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

func dispatcher(s state.StateInterface, e execute.ExecuteInterface, a aliveConfig) {
	for _, alive := range a.Alive {
		ticker := time.NewTicker(time.Duration(aliveProbeInterval) * aliveProbeIntervalUnit)
		go func(ticker *time.Ticker, item aliveItem, e execute.ExecuteInterface, s state.StateInterface) {
			aliveData, err := json.Marshal(item.Data)
			if err != nil {
				log.Printf("unable to parse alive config %v: %s, skipping...", item, err)
				return
			}
			var lastRun time.Time
			for {
				select {
				case <-ticker.C:
					now := time.Now()
					// Execute only when now - LastSeen > alive.ProcessAfter * aliveProcessAfterUnit
					if now.Sub(s.GetLastSeen()) > time.Duration(item.ProcessAfter)*aliveProcessAfterUnit {
						// Execute only when now - lastRun > alive.MinInterval * aliveMinIntervalUnit
						if now.Sub(lastRun) > time.Duration(item.MinInterval)*aliveMinIntervalUnit {
							lastRun = now
							if err := e.Run(&state.Action{
								Kind: item.Kind,
								Data: string(aliveData),
							}); err != nil {
								log.Printf("unable to run alive probe: %s", err)
							}
						}
					}
				}
			}
		}(ticker, alive, e, s)
	}

	processMessagesTicker := time.NewTicker(time.Duration(processMessagesInterval) * processMessagesIntervalUnit)
	for {
		select {
		case <-processMessagesTicker.C:
			for _, a := range s.GetActions() {
				if a.Processed == 2 {
					continue
				}
				now := time.Now()
				if now.Sub(s.GetLastSeen()) > time.Duration(a.ProcessAfter)*processAfterIntervalUnit {
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
