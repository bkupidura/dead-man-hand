package api

import (
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
	VaultURL        string
	VaultClientUUID string
	DMHEnabled      bool
	VaultEnabled    bool
}
