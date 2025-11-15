package execute

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"dmh/internal/state"
)

type ExecuteJSONPost struct {
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Data        map[string]any    `json:"data"`
	SuccessCode []int             `json:"success_code"`
}

// Run will sent HTTP POST request which application/json encoding.
func (d *ExecuteJSONPost) Run() error {
	marshaledData, err := jsonMarshal(d.Data)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", d.URL, bytes.NewBuffer(marshaledData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range d.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if slices.Contains(d.SuccessCode, resp.StatusCode) {
		return nil
	}

	return fmt.Errorf("received wrong status code %d", resp.StatusCode)
}

func (d *ExecuteJSONPost) Populate(a *state.Action) error {
	err := json.Unmarshal([]byte(a.Data), &d)
	if err != nil {
		return err
	}
	if d.URL == "" {
		return fmt.Errorf("url must be provided")
	}
	if len(d.SuccessCode) == 0 {
		return fmt.Errorf("success_code must be provided")
	}
	if len(d.Data) == 0 {
		return fmt.Errorf("data must be provided")
	}
	return nil
}

func (d *ExecuteJSONPost) PopulateConfig(e *Execute) error {
	return nil
}
