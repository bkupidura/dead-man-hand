package execute

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"dmh/internal/state"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/require"
)

type mockSMTPHandler struct {
	authShouldFail bool
	fromShouldFail bool
	sessions       []*mockSMTPSession
}

func (e *mockSMTPHandler) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	s := &mockSMTPSession{handler: e}
	e.sessions = append(e.sessions, s)
	return s, nil
}

func newSMTPHandler(authShouldFail, fromShouldFail bool) *mockSMTPHandler {
	return &mockSMTPHandler{
		authShouldFail: authShouldFail,
		fromShouldFail: fromShouldFail,
	}
}

type mockSMTPSession struct {
	from    string
	to      []string
	body    string
	handler *mockSMTPHandler
	auth    bool
}

func (s *mockSMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	if s.handler.fromShouldFail {
		return &smtp.SMTPError{
			Code:    502,
			Message: "mockSMTPSessionMail error",
		}
	}
	s.from = from
	return nil
}

func (s *mockSMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *mockSMTPSession) Data(r io.Reader) error {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	s.body = buf.String()
	return nil
}

func (s *mockSMTPSession) Reset() {}

func (s *mockSMTPSession) Logout() error { return nil }

func (s *mockSMTPSession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *mockSMTPSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if s.handler.authShouldFail {
			return fmt.Errorf("mockAuthShouldFail error")
		}
		s.auth = true
		return nil
	}), nil
}

func TestMailRun(t *testing.T) {
	tests := []struct {
		inputPlugin            *ExecuteMail
		inputMockSMTPHandler   *mockSMTPHandler
		inputSMTPServerWithTLS bool
		expectedError          bool
	}{
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:  "test",
					Password:  "test",
					Server:    "",
					TLSPolicy: "tls_mandatory",
				},
			},
			expectedError: true,
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:  "test",
					Password:  "test",
					Server:    "",
					TLSPolicy: "tls_opportunistic",
				},
			},
			expectedError: true,
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:  "test",
					Password:  "test",
					Server:    "",
					TLSPolicy: "no_tls",
				},
			},
			expectedError: true,
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:  "",
					Password:  "",
					Server:    "",
					TLSPolicy: "tls_mandatory",
				},
			},
			expectedError: true,
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:  "test",
					Password:  "test",
					Server:    "test",
					TLSPolicy: "tls_mandatory",
					From:      "invalid",
				},
			},
			expectedError: true,
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:  "test",
					Password:  "test",
					Server:    "test",
					TLSPolicy: "tls_mandatory",
					From:      "test@test.com",
				},
				Message:     "Test",
				Subject:     "test subject",
				Destination: []string{"invalid"},
			},
			expectedError: true,
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:  "test",
					Password:  "test",
					Server:    "test",
					TLSPolicy: "tls_mandatory",
					From:      "test@test.com",
				},
				Message:     "Test",
				Subject:     "test subject",
				Destination: []string{"test@test.com"},
			},
			expectedError: true,
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:    "",
					Password:    "",
					Server:      "localhost",
					TLSPolicy:   "tls_mandatory",
					TLSInsecure: true,
					From:        "test@test.com",
				},
				Message:     "Test",
				Subject:     "test subject",
				Destination: []string{"test1@test.com"},
			},
			inputSMTPServerWithTLS: true,
			inputMockSMTPHandler:   newSMTPHandler(false, false),
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:    "test",
					Password:    "test",
					Server:      "localhost",
					TLSPolicy:   "tls_mandatory",
					TLSInsecure: true,
					From:        "test@test.com",
				},
				Message:     "Test",
				Subject:     "test subject",
				Destination: []string{"test1@test.com"},
			},
			inputSMTPServerWithTLS: true,
			inputMockSMTPHandler:   newSMTPHandler(false, false),
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:    "test",
					Password:    "test",
					Server:      "localhost",
					TLSPolicy:   "tls_mandatory",
					TLSInsecure: true,
					From:        "test@test.com",
				},
				Message:     "Test",
				Subject:     "test subject",
				Destination: []string{"test1@test.com", "valid@valid.com"},
			},
			inputSMTPServerWithTLS: true,
			inputMockSMTPHandler:   newSMTPHandler(false, false),
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:    "test",
					Password:    "test",
					Server:      "localhost",
					TLSPolicy:   "tls_opportunistic",
					TLSInsecure: true,
					From:        "test@test.com",
				},
				Message:     "Test",
				Subject:     "test subject",
				Destination: []string{"test1@test.com"},
			},
			inputSMTPServerWithTLS: true,
			inputMockSMTPHandler:   newSMTPHandler(false, false),
		},
		{
			inputPlugin: &ExecuteMail{
				config: MailConfig{
					Username:    "test",
					Password:    "test",
					Server:      "localhost",
					TLSPolicy:   "no_tls",
					TLSInsecure: false,
					From:        "test@test.com",
				},
				Message:     "Test",
				Subject:     "test subject",
				Destination: []string{"test1@test.com"},
			},
			inputSMTPServerWithTLS: false,
			inputMockSMTPHandler:   newSMTPHandler(false, false),
		},
	}
	generateCerts := exec.Command("sh", "-c", `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/C=US/ST=State/L=Locality/O=Organization/CN=localhost"`)
	err := generateCerts.Run()
	require.Nil(t, err)
	defer os.Remove("key.pem")
	defer os.Remove("cert.pem")
	for _, test := range tests {
		var smtpHandler *mockSMTPHandler
		var err error
		var tlsConfig *tls.Config
		var smtpServer *smtp.Server
		if test.inputMockSMTPHandler != nil {
			smtpHandler = test.inputMockSMTPHandler
			smtpServer = smtp.NewServer(smtpHandler)
			smtpServer.Addr = ":587"
			smtpServer.Domain = "localhost"
			smtpServer.AllowInsecureAuth = true
			if test.inputSMTPServerWithTLS {
				tlsConfig = &tls.Config{
					Certificates: make([]tls.Certificate, 1),
				}
				tlsConfig.Certificates[0], err = tls.LoadX509KeyPair("cert.pem", "key.pem")
				require.Nil(t, err)
				smtpServer.TLSConfig = tlsConfig
				smtpServer.Addr = ":587"
			} else {
				smtpServer.Addr = ":25"
			}
			go func() {
				err := smtpServer.ListenAndServe()
				require.Nil(t, err)
			}()
			defer func() {
				smtpServer.Close()
			}()

		}

		plugin := test.inputPlugin
		err = plugin.Run()

		if test.expectedError {
			require.NotNil(t, err)
		} else {
			require.Nil(t, err)
		}
		if test.inputMockSMTPHandler != nil {
			var sessionIdx int
			if test.inputSMTPServerWithTLS {
				sessionIdx = 1
			} else {
				sessionIdx = 0
			}
			require.Equal(t, test.inputPlugin.config.From, smtpHandler.sessions[sessionIdx].from)
			require.Equal(t, test.inputPlugin.Destination, smtpHandler.sessions[sessionIdx].to)
			var destinationFormatted []string
			for _, destination := range test.inputPlugin.Destination {
				destinationFormatted = append(destinationFormatted, fmt.Sprintf("<%s>", destination))
			}
			bodyRegex := regexp.MustCompile(fmt.Sprintf(`Subject: %s(?s).*From: <%s>(?s).*To: %s(?s).*%s`, test.inputPlugin.Subject, test.inputPlugin.config.From, strings.Join(destinationFormatted, ", "), test.inputPlugin.Message))
			require.True(t, bodyRegex.MatchString(smtpHandler.sessions[sessionIdx].body))
			err = smtpServer.Close()
			require.Nil(t, err)
		}
	}
}

func TestMailPopulate(t *testing.T) {
	tests := []struct {
		inputPlugin   *ExecuteMail
		inputAction   *state.Action
		expectedError string
	}{
		{
			inputPlugin:   &ExecuteMail{},
			inputAction:   &state.Action{Kind: "mail", Data: `{"broken"`},
			expectedError: "unexpected end of JSON input",
		},
		{
			inputPlugin:   &ExecuteMail{},
			inputAction:   &state.Action{Kind: "mail", Data: `{"message": ""}`},
			expectedError: "message must be provided",
		},
		{
			inputPlugin:   &ExecuteMail{},
			inputAction:   &state.Action{Kind: "mail", Data: `{"message": "test", "subject":""}`},
			expectedError: "subject must be provided",
		},
		{
			inputPlugin:   &ExecuteMail{},
			inputAction:   &state.Action{Kind: "mail", Data: `{"message": "test", "subject": "test2", "destination":[]}`},
			expectedError: "destination must be provided",
		},
		{
			inputPlugin:   &ExecuteMail{},
			inputAction:   &state.Action{Kind: "mail", Data: `{"message": "test", "subject": "test2", "destination": ["test@test.com", "test@"]}`},
			expectedError: "destination must be a valid address mail: missing '@' or angle-addr",
		},
		{
			inputPlugin: &ExecuteMail{},
			inputAction: &state.Action{Kind: "mail", Data: `{"message": "test", "subject": "test2", "destination": ["test@test.com", "second@test.com.pl"]}`},
		},
	}
	for _, test := range tests {
		plugin := test.inputPlugin
		err := plugin.Populate(test.inputAction)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}
	}
}

func TestMailPopulateConfig(t *testing.T) {
	tests := []struct {
		inputExecute   *Execute
		expectedError  error
		expectedConfig MailConfig
	}{
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username: "",
					Password: "password",
				},
			},
			expectedError: fmt.Errorf("username and password must be set together"),
			expectedConfig: MailConfig{
				Username: "",
				Password: "password",
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username: "username",
					Password: "",
				},
			},
			expectedError: fmt.Errorf("username and password must be set together"),
			expectedConfig: MailConfig{
				Username: "username",
				Password: "",
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username: "username",
					Password: "password",
					Server:   "",
				},
			},
			expectedError: fmt.Errorf("server must be provided"),
			expectedConfig: MailConfig{
				Username: "username",
				Password: "password",
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username: "username",
					Password: "password",
					Server:   "test",
					From:     "",
				},
			},
			expectedError: fmt.Errorf("from must be a valid address mail: no address"),
			expectedConfig: MailConfig{
				Username: "username",
				Password: "password",
				Server:   "test",
				From:     "",
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username: "username",
					Password: "password",
					Server:   "test",
					From:     "test",
				},
			},
			expectedError: fmt.Errorf("from must be a valid address mail: missing '@' or angle-addr"),
			expectedConfig: MailConfig{
				Username: "username",
				Password: "password",
				Server:   "test",
				From:     "test",
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username:  "username",
					Password:  "password",
					Server:    "test",
					From:      "test@test.com",
					TLSPolicy: "wrong",
				},
			},
			expectedError: fmt.Errorf("tls_policy must be tls_mandatory, tls_opportunistic or no_tls"),
			expectedConfig: MailConfig{
				Username:  "username",
				Password:  "password",
				Server:    "test",
				From:      "test@test.com",
				TLSPolicy: "wrong",
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username: "username",
					Password: "password",
					Server:   "test",
					From:     "test@test.com",
				},
			},
			expectedConfig: MailConfig{
				Username:  "username",
				Password:  "password",
				Server:    "test",
				From:      "test@test.com",
				TLSPolicy: "tls_mandatory",
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					Username:  "username",
					Password:  "password",
					Server:    "test",
					From:      "test@test.com",
					TLSPolicy: "no_tls",
				},
			},
			expectedConfig: MailConfig{
				Username:  "username",
				Password:  "password",
				Server:    "test",
				From:      "test@test.com",
				TLSPolicy: "no_tls",
			},
		},
	}
	for _, test := range tests {
		plugin := &ExecuteMail{}
		err := plugin.PopulateConfig(test.inputExecute)
		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedConfig, plugin.config)
	}
}
