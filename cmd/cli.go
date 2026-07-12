package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"dmh/internal/state"

	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

var (
	// mocks for tests
	newRequest  = http.NewRequest
	jsonMarshal = json.Marshal
	getClient   = func(cmd *cli.Command) *http.Client {
		return &http.Client{Timeout: 5 * time.Second}
	}
)

const defaultServerAddr = "http://127.0.0.1:8080"

func createCLI() *cli.Command {
	return &cli.Command{
		Name:    "dmh-client",
		Usage:   "Manage dead-man-hand",
		Version: "1.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Value:   defaultServerAddr,
				Usage:   "HTTP server address",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "alive",
				Usage: "Alive operations",
				Commands: []*cli.Command{
					{
						Name:   "update",
						Usage:  "Update last seen information",
						Action: updateAlive,
					},
				},
			},
			{
				Name:  "action",
				Usage: "Action operations",
				Commands: []*cli.Command{
					{
						Name:    "list",
						Aliases: []string{"ls"},
						Usage:   "List all actions",
						Action:  listActions,
					},
					{
						Name:  "add",
						Usage: "Add a new action or multiple actions from a file",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "data",
								Aliases: []string{"d"},
								Usage:   "Action data (json formatted). Ignored if --file is provided.",
							},
							&cli.StringFlag{
								Name:  "comment",
								Usage: "Action comment (will be stored unencrypted). Ignored if --file is provided.",
							},
							&cli.StringFlag{
								Name:    "kind",
								Aliases: []string{"k"},
								Usage:   "Action kind. Ignored if --file is provided.",
							},
							&cli.IntFlag{
								Name:    "process-after",
								Aliases: []string{"p"},
								Usage:   "Process action after <param> hours from last seen. Required. Ignored if --file is provided.",
							},
							&cli.IntFlag{
								Name:    "min-interval",
								Aliases: []string{"i"},
								Usage:   "Process action after <param> hours from last run. If min-interval > 0, action will be run FOREVER and NOT ONCE. USE WITH CAUTION!",
								Value:   0,
							},
							&cli.StringFlag{
								Name:    "file",
								Aliases: []string{"f"},
								Usage:   "Path to YAML file containing actions to add",
							},
						},
						Action: addAction,
					},
					{
						Name:  "test",
						Usage: "Test action",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "data",
								Aliases:  []string{"d"},
								Usage:    "Action data (json formatted)",
								Required: true,
							},
							&cli.StringFlag{
								Name:     "kind",
								Aliases:  []string{"k"},
								Usage:    "Action kind",
								Required: true,
							},
						},
						Action: testAction,
					},
					{
						Name:  "delete",
						Usage: "Delete a action",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "uuid",
								Usage:    "Action UUID to delete",
								Required: true,
							},
						},
						Action: deleteAction,
					},
				},
			},
		},
	}
}

func main() {
	cmd := createCLI()
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func updateAlive(ctx context.Context, cmd *cli.Command) error {
	client := getClient(cmd)
	server := cmd.String("server")
	endpointAddress, err := url.JoinPath(server, "api", "alive")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}
	resp, err := client.Get(endpointAddress)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func listActions(ctx context.Context, cmd *cli.Command) error {
	client := getClient(cmd)
	server := cmd.String("server")
	endpointAddress, err := url.JoinPath(server, "api", "action", "store")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}
	resp, err := client.Get(endpointAddress)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

// createAction validates and sends a single action to the server
func createAction(cmd *cli.Command, action *state.Action) error {
	if err := action.Validate(); err != nil {
		return err
	}

	payload, err := jsonMarshal(action)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	endpointAddress, err := url.JoinPath(cmd.String("server"), "api", "action", "store")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}

	resp, err := getClient(cmd).Post(endpointAddress, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// addAction is the CLI handler. If --file is provided, reads YAML and creates each action.
// Otherwise creates a single action from flags.
// All file entries are validated before anything is sent to the server, but server-side
// failures are reported per action - earlier actions may already be added when a later one fails.
func addAction(ctx context.Context, cmd *cli.Command) error {
	if filePath := cmd.String("file"); filePath != "" {
		actions, err := loadActionsFromFile(filePath)
		if err != nil {
			return fmt.Errorf("unable to load actions from file: %w", err)
		}
		if len(actions) == 0 {
			return fmt.Errorf("no actions found in file")
		}

		var failed int
		for i, action := range actions {
			if err := createAction(cmd, action); err != nil {
				fmt.Fprintf(os.Stderr, "action %d: %s\n", i+1, err)
				failed++
			}
		}

		if failed > 0 {
			return fmt.Errorf("%d of %d actions failed to add", failed, len(actions))
		}
		return nil
	}

	return createAction(cmd, &state.Action{
		Kind:         cmd.String("kind"),
		Data:         cmd.String("data"),
		ProcessAfter: cmd.Int("process-after"),
		MinInterval:  cmd.Int("min-interval"),
		Comment:      cmd.String("comment"),
	})
}

// actionData can unmarshal from both a YAML string and a YAML object/mapping.
// When a YAML string, it is passed through unchanged.
// When a YAML object, it is marshaled to a JSON string for the API.
type actionData struct {
	Value string
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *actionData) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		var m map[string]any
		if err := node.Decode(&m); err != nil {
			return err
		}
		b, err := jsonMarshal(m)
		if err != nil {
			return err
		}
		d.Value = string(b)
		return nil
	}
	return node.Decode(&d.Value)
}

// actionFileEntry describes single action read from a YAML file.
type actionFileEntry struct {
	Kind         string     `yaml:"kind"`
	Data         actionData `yaml:"data"`
	ProcessAfter int        `yaml:"process_after"`
	MinInterval  int        `yaml:"min_interval"`
	Comment      string     `yaml:"comment"`
}

// loadActionsFromFile reads a YAML file containing a list of actions.
// It accepts data as either a JSON string or a native YAML object.
// It validates each entry inline and returns the first validation error found,
// indexed by position (1-based) so users can fix their file quickly.
func loadActionsFromFile(path string) ([]*state.Action, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rawEntries []*actionFileEntry
	if err := yaml.Unmarshal(data, &rawEntries); err != nil {
		return nil, err
	}

	actions := make([]*state.Action, 0, len(rawEntries))
	for i, e := range rawEntries {
		a := &state.Action{
			Kind:         e.Kind,
			Data:         e.Data.Value,
			ProcessAfter: e.ProcessAfter,
			MinInterval:  e.MinInterval,
			Comment:      e.Comment,
		}
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("action #%d: %w", i+1, err)
		}
		actions = append(actions, a)
	}
	return actions, nil
}

func testAction(ctx context.Context, cmd *cli.Command) error {
	data := cmd.String("data")
	kind := cmd.String("kind")

	if data == "" {
		return fmt.Errorf("data is required")
	}
	if kind == "" {
		return fmt.Errorf("kind is required")
	}

	payload := map[string]any{
		"kind":          kind,
		"data":          data,
		"process_after": 10,
	}

	jsonData, err := jsonMarshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	endpointAddress, err := url.JoinPath(cmd.String("server"), "api", "action", "test")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}

	resp, err := getClient(cmd).Post(endpointAddress, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("Action tested successfully")
	return nil
}

func deleteAction(ctx context.Context, cmd *cli.Command) error {
	client := getClient(cmd)
	server := cmd.String("server")
	uuid := cmd.String("uuid")

	if uuid == "" {
		return fmt.Errorf("uuid is required")
	}

	endpointAddress, err := url.JoinPath(server, "api", "action", "store", uuid)
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}

	req, err := newRequest("DELETE", endpointAddress, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("Action deleted successfully")
	return nil
}
