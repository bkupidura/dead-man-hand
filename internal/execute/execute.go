package execute

import (
	"encoding/json"
	"fmt"

	"dmh/internal/state"
)

var (
	// mocks for tests
	jsonMarshal = json.Marshal
)

// executeData describes interface for every execute plugin.
type executeData interface {
	Run() error // Run executes plugin
}

// ExecuteInterface describes interface for Execute.
type ExecuteInterface interface {
	Run(*state.Action) error
	CheckAction(*state.Action) error
}

// Execute stores internal data.
type Execute struct {
	bulkSMSConf     BulkSMSConfig
	mailConf        MailConfig
	execConf        ExecConfig
	signedURLSecret string
	signedURLTTL    int
}

// New returns new instance of Execute.
func New(opts *Options) (ExecuteInterface, error) {
	e := &Execute{
		bulkSMSConf:     opts.BulkSMSConf,
		mailConf:        opts.MailConf,
		execConf:        opts.ExecConf,
		signedURLSecret: opts.SignedURLSecret,
		signedURLTTL:    opts.SignedURLTTL,
	}

	return e, nil
}

// Run will execute Action.
func (e *Execute) Run(a *state.Action) error {
	action := *a
	e.expandSigAuth(&action)
	data, err := e.prepare(&action)
	if err != nil {
		return err
	}
	return data.Run()
}

// CheckAction validates Action without running it.
func (e *Execute) CheckAction(a *state.Action) error {
	_, err := e.prepare(a)
	return err
}

// prepare unmarshals Action.Data into the matching plugin, then populates its config and data.
func (e *Execute) prepare(action *state.Action) (executeData, error) {
	switch action.Kind {
	case "json_post":
		data := &ExecuteJSONPost{}
		if err := data.populate(action); err != nil {
			return nil, err
		}
		return data, nil
	case "bulksms":
		data := &ExecuteBulkSMS{}
		if err := data.populateConfig(e); err != nil {
			return nil, err
		}
		if err := data.populate(action); err != nil {
			return nil, err
		}
		return data, nil
	case "mail":
		data := &ExecuteMail{}
		if err := data.populateConfig(e); err != nil {
			return nil, err
		}
		if err := data.populate(action); err != nil {
			return nil, err
		}
		return data, nil
	case "dummy":
		data := &ExecuteDummy{}
		if err := data.populate(action); err != nil {
			return nil, err
		}
		if err := data.populateConfig(e); err != nil {
			return nil, err
		}
		return data, nil
	case "exec":
		data := &ExecuteExec{}
		if err := data.populateConfig(e); err != nil {
			return nil, err
		}
		if err := data.populate(action); err != nil {
			return nil, err
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unknown kind %s", action.Kind)
	}
}
