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

// ExecuteData describes interface for every execute plugin.
type ExecuteData interface {
	Run() error                    // Run executes plugin
	Populate(*state.Action) error  // Populate will populate plugin struct with Action.Data
	PopulateConfig(*Execute) error // PopulateConfig will populate plugin config struct from Executor config
}

// ExecuteInterface describes interface for Execute.
type ExecuteInterface interface {
	Run(*state.Action) error
}

// Execute stores internal data.
type Execute struct {
	bulkSMSConf BulkSMSConfig
	mailConf    MailConfig
}

// New returns new instance of Execute.
func New(opts *Options) (ExecuteInterface, error) {
	e := &Execute{
		bulkSMSConf: opts.BulkSMSConf,
		mailConf:    opts.MailConf,
	}

	return e, nil
}

// Run will execute Action).
func (e *Execute) Run(a *state.Action) error {
	data, err := UnmarshalActionData(a)
	if err != nil {
		return err
	}
	if err := data.PopulateConfig(e); err != nil {
		return err
	}
	return data.Run()
}

// UnmarshalActionData will unmarshal Action.Data into valid plugin which can be executed.
func UnmarshalActionData(action *state.Action) (ExecuteData, error) {
	switch action.Kind {
	case "json_post":
		data := &ExecuteJSONPost{}
		err := data.Populate(action)
		return data, err
	case "bulksms":
		data := &ExecuteBulkSMS{}
		err := data.Populate(action)
		return data, err
	case "mail":
		data := &ExecuteMail{}
		err := data.Populate(action)
		return data, err
	case "dummy":
		data := &ExecuteDummy{}
		err := data.Populate(action)
		return data, err
	default:
		return nil, fmt.Errorf("unknown kind %s", action.Kind)
	}
}
