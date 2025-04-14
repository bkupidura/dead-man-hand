package execute

import (
	"encoding/json"
	"fmt"
	"log"

	"dmh/internal/state"
)

type ExecuteDummy struct {
	Message              string `json:"message"`
	FailOnRun            bool   `json:"fail_on_run"`
	FailOnPopulate       bool   `json:"fail_on_populate"`
	FailOnPopulateConfig bool   `json:"fail_on_populate_config"`
}

// Run will log Message. Its should be only used for tests.
func (d *ExecuteDummy) Run() error {
	if d.FailOnRun {
		return fmt.Errorf("FailOnRun error")
	}
	log.Printf("run for execute dummy %+v", d)
	return nil
}

func (d *ExecuteDummy) Populate(a *state.Action) error {
	err := json.Unmarshal([]byte(a.Data), &d)
	if err != nil {
		return err
	}

	if d.FailOnPopulate {
		return fmt.Errorf("FailOnPopulate error")
	}

	if d.Message == "" {
		return fmt.Errorf("message must be provided")
	}

	return nil
}

func (d *ExecuteDummy) PopulateConfig(e *Execute) error {
	if d.FailOnPopulateConfig {
		return fmt.Errorf("FailOnPopulateConfig error")
	}
	return nil
}
