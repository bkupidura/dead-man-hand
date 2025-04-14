package execute

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"dmh/internal/state"
)

var (
	endpoint = "https://api.bulksms.com/v1/messages"
)

type BulkSMSToken struct {
	ID     string `koanf:"id"`
	Secret string `koanf:"secret"`
}

type BulkSMSConfig struct {
	RoutingGroup string       `koanf:"routing_group"`
	Token        BulkSMSToken `koanf:"token"`
}

type ExecuteBulkSMS struct {
	Message     string   `json:"message"`
	Destination []string `json:"destination"`
	config      BulkSMSConfig
}

type sendRequest struct {
	Body         string   `json:"body"`
	Encoding     string   `json:"encoding"`
	RoutingGroup string   `json:"routingGroup"`
	To           []string `json:"to"`
}

// Run will sent SMS over https://www.bulksms.com/ HTTP API.
func (d *ExecuteBulkSMS) Run() error {
	sr := &sendRequest{
		Body:         d.Message,
		Encoding:     "UNICODE",
		RoutingGroup: strings.ToUpper(d.config.RoutingGroup),
		To:           d.Destination,
	}
	marshaledData, err := jsonMarshal(sr)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(marshaledData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	authPair := fmt.Sprintf("%s:%s", d.config.Token.ID, d.config.Token.Secret)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(authPair))))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("received wrong status code %d", resp.StatusCode)
	}

	return nil
}

func (d *ExecuteBulkSMS) Populate(a *state.Action) error {
	err := json.Unmarshal([]byte(a.Data), &d)
	if err != nil {
		return err
	}
	if d.Message == "" {
		return fmt.Errorf("message must be provided")
	}
	if len(d.Destination) == 0 {
		return fmt.Errorf("destination must be provided")
	}
	pattern := regexp.MustCompile(`^[+\d]+$`)
	for _, destination := range d.Destination {
		if !pattern.MatchString(destination) {
			return fmt.Errorf("destination must be a number")
		}
	}
	return nil
}

func (d *ExecuteBulkSMS) PopulateConfig(e *Execute) error {
	d.config = e.bulkSMSConf
	if d.config.Token.ID == "" || d.config.Token.Secret == "" {
		return fmt.Errorf("config token id and secret must be provided")
	}

	if d.config.RoutingGroup == "" {
		d.config.RoutingGroup = "standard"
	}
	validRoutingGroup := false
	for _, allowedValue := range []string{"economy", "standard", "premium"} {
		if d.config.RoutingGroup == allowedValue {
			validRoutingGroup = true
			break
		}
	}
	if !validRoutingGroup {
		return fmt.Errorf("routing_group must be one of economy, standard or premium")
	}
	return nil
}
