package execute

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/mail"
	"slices"

	"dmh/internal/state"

	gomail "github.com/wneessen/go-mail"
)

type MailConfig struct {
	Username    string `koanf:"username"`
	Password    string `koanf:"password"`
	Server      string `koanf:"server"`
	From        string `koanf:"from"`
	TLSPolicy   string `koanf:"tls_policy"`
	TLSInsecure bool   `koanf:"tls_insecure"`
}

type ExecuteMail struct {
	Message     string   `json:"message"`
	Destination []string `json:"destination"`
	Subject     string   `json:"subject"`
	config      MailConfig
}

// Run will sent email over SMTP.
func (d *ExecuteMail) Run() error {
	var tlsPolicy gomail.Option
	switch d.config.TLSPolicy {
	case "tls_mandatory":
		tlsPolicy = gomail.WithTLSPortPolicy(gomail.TLSMandatory)
	case "tls_opportunistic":
		tlsPolicy = gomail.WithTLSPortPolicy(gomail.TLSOpportunistic)
	case "no_tls":
		tlsPolicy = gomail.WithTLSPortPolicy(gomail.NoTLS)
	}

	var client *gomail.Client
	var err error

	if d.config.Username != "" {
		client, err = gomail.NewClient(d.config.Server, tlsPolicy, gomail.WithSMTPAuth(gomail.SMTPAuthPlain), gomail.WithUsername(d.config.Username), gomail.WithPassword(d.config.Password))
	} else {
		client, err = gomail.NewClient(d.config.Server, tlsPolicy)
	}

	if err != nil {
		return err
	}

	if d.config.TLSInsecure {
		client.SetTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
		})
	}

	message := gomail.NewMsg()
	if err := message.From(d.config.From); err != nil {
		return err
	}
	if err := message.To(d.Destination...); err != nil {
		return err
	}

	message.Subject(d.Subject)
	message.SetBodyString(gomail.TypeTextPlain, d.Message)

	if err := client.DialAndSend(message); err != nil {
		return err
	}

	return nil
}

func (d *ExecuteMail) Populate(a *state.Action) error {
	err := json.Unmarshal([]byte(a.Data), &d)
	if err != nil {
		return err
	}
	if d.Message == "" {
		return fmt.Errorf("message must be provided")
	}
	if d.Subject == "" {
		return fmt.Errorf("subject must be provided")
	}
	if len(d.Destination) == 0 {
		return fmt.Errorf("destination must be provided")
	}

	for _, destination := range d.Destination {
		if _, err := mail.ParseAddress(destination); err != nil {
			return fmt.Errorf("destination must be a valid address %s", err)
		}
	}

	return nil
}

func (d *ExecuteMail) PopulateConfig(e *Execute) error {
	d.config = e.mailConf
	if (d.config.Username == "" && d.config.Password != "") || (d.config.Username != "" && d.config.Password == "") {
		return fmt.Errorf("username and password must be set together")
	}
	if d.config.Server == "" {
		return fmt.Errorf("server must be provided")
	}
	if _, err := mail.ParseAddress(d.config.From); err != nil {
		return fmt.Errorf("from must be a valid address %s", err)
	}

	if d.config.TLSPolicy == "" {
		d.config.TLSPolicy = "tls_mandatory"
	}

	if !slices.Contains([]string{"tls_mandatory", "tls_opportunistic", "no_tls"}, d.config.TLSPolicy) {
		return fmt.Errorf("tls_policy must be tls_mandatory, tls_opportunistic or no_tls")
	}

	return nil
}
