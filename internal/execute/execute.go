package execute

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"dmh/internal/crypt"
	"dmh/internal/state"
)

// sigAuthPlaceholder matches {sig_auth:<page>} in action data, which is
// expanded on execution into freshly signed url /<page> path with
// e and s query parameters attached.
var sigAuthPlaceholder = regexp.MustCompile(`\{sig_auth:([a-z0-9_-]+)\}`)

var (
	// mocks for tests
	jsonMarshal = json.Marshal
	timeNow     = time.Now
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
	bulkSMSConf     BulkSMSConfig
	mailConf        MailConfig
	signedURLSecret string
	signedURLTTL    int
}

// New returns new instance of Execute.
func New(opts *Options) (ExecuteInterface, error) {
	e := &Execute{
		bulkSMSConf:     opts.BulkSMSConf,
		mailConf:        opts.MailConf,
		signedURLSecret: opts.SignedURLSecret,
		signedURLTTL:    opts.SignedURLTTL,
	}

	return e, nil
}

// Run will execute Action).
func (e *Execute) Run(a *state.Action) error {
	e.expandSigAuth(a)
	data, err := UnmarshalActionData(a)
	if err != nil {
		return err
	}
	if err := data.PopulateConfig(e); err != nil {
		return err
	}
	return data.Run()
}

// expandSigAuth replaces sigAuthPlaceholder occurrences in action data with
// freshly signed /<page> path.
// When auth disabled, placeholder is expanded to plain page path.
func (e *Execute) expandSigAuth(a *state.Action) {
	a.Data = sigAuthPlaceholder.ReplaceAllStringFunc(a.Data, func(placeholder string) string {
		path := "/" + sigAuthPlaceholder.FindStringSubmatch(placeholder)[1]
		sigAuth := path
		if e.signedURLSecret != "" {
			expiresAt := timeNow().Add(time.Duration(e.signedURLTTL) * time.Hour)
			sigAuth = crypt.SignURL(e.signedURLSecret, path, expiresAt)
		}
		return strings.TrimPrefix(sigAuth, "/")
	})
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
