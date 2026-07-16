package api

import (
	"dmh/internal/auth"
	"dmh/internal/execute"
	"dmh/internal/state"
	"dmh/internal/vault"
)

var (
	HTTPPort = 8080
)

type Options struct {
	Vault           vault.VaultInterface
	State           state.StateInterface
	Execute         execute.ExecuteInterface
	Auth            auth.Config
	VaultURL        string
	VaultClientUUID string
	VaultToken      string
	DMHEnabled      bool
	VaultEnabled    bool
	Debug           bool
}
