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

	"dmh/internal/crypt"

	"dmh/internal/state"

	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

const httpClientTimeout = 15 * time.Second

var (
	// mocks for tests
	newRequest  = http.NewRequest
	jsonMarshal = json.Marshal
	getClient   = func(cmd *cli.Command) *http.Client {
		return &http.Client{Timeout: httpClientTimeout}
	}
	newBearerToken = crypt.NewBearerToken
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
			&cli.StringFlag{
				Name:    "token",
				Aliases: []string{"t"},
				Usage:   "Bearer token used to authenticate against DMH server",
				Sources: cli.EnvVars("DMH_TOKEN"),
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
								Name:    "data",
								Aliases: []string{"d"},
								Usage:   "Action data (json formatted). Ignored if --file is provided.",
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
							&cli.StringFlag{
								Name:    "file",
								Aliases: []string{"f"},
								Usage:   "Path to YAML file containing actions to test. WARNING: ALL actions from file will be executed immediately",
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
			{
				Name:  "auth",
				Usage: "Authentication management",
				Commands: []*cli.Command{
					{
						Name:   "generate-bearer",
						Usage:  "Generate a new bearer token (prints plaintext bearer token + its sha256)",
						Action: genBearer,
					},
				},
			},
		},
	}
}

// genBearer generates bearer token.
func genBearer(ctx context.Context, cmd *cli.Command) error {
	token, err := newBearerToken()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "BearerToken: %s\n", token.Plaintext)
	fmt.Fprintf(os.Stdout, "SHA256: %s\n", token.Hash)
	return nil
}
func main() {
	cmd := createCLI()
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
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

// doRequest sends HTTP request to DMH server with optional bearer token.
func doRequest(cmd *cli.Command, method string, url string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewBuffer(body)
	}
	req, err := newRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	if token := cmd.String("token"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return getClient(cmd).Do(req)
}

// sendAction validates and sends a single action to given server endpoint.
func sendAction(cmd *cli.Command, action *state.Action, endpoint string, wantStatus int) error {
	if err := action.Validate(); err != nil {
		return err
	}

	payload, err := jsonMarshal(action)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	endpointAddress, err := url.JoinPath(cmd.String("server"), "api", "action", endpoint)
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}

	resp, err := doRequest(cmd, "POST", endpointAddress, payload)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != wantStatus {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// createAction validates and sends a single action to the server
func createAction(cmd *cli.Command, action *state.Action) error {
	return sendAction(cmd, action, "store", http.StatusCreated)
}

// sendTestAction validates and sends a single action to the server for immediate execution.
func sendTestAction(cmd *cli.Command, action *state.Action) error {
	return sendAction(cmd, action, "test", http.StatusOK)
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

// processActionsFromFile loads actions from a YAML file and sends each one with send.
// All file entries are validated before anything is sent to the server, but server-side
// failures are reported per action - earlier actions are already sent when a later one fails.
func processActionsFromFile(cmd *cli.Command, path string, send func(*cli.Command, *state.Action) error) error {
	actions, err := loadActionsFromFile(path)
	if err != nil {
		return fmt.Errorf("unable to load actions from file: %w", err)
	}
	if len(actions) == 0 {
		return fmt.Errorf("no actions found in file")
	}

	var failed int
	for i, action := range actions {
		if err := send(cmd, action); err != nil {
			fmt.Fprintf(os.Stderr, "action %d: %s\n", i+1, err)
			failed++
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d actions failed", failed, len(actions))
	}
	return nil
}

func updateAlive(ctx context.Context, cmd *cli.Command) error {
	server := cmd.String("server")
	endpointAddress, err := url.JoinPath(server, "api", "alive")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}
	resp, err := doRequest(cmd, "GET", endpointAddress, nil)
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
	server := cmd.String("server")
	endpointAddress, err := url.JoinPath(server, "api", "action", "store")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}
	resp, err := doRequest(cmd, "GET", endpointAddress, nil)
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

// addAction is the CLI handler. If --file is provided, reads YAML and creates each action.
// Otherwise creates a single action from flags.
func addAction(ctx context.Context, cmd *cli.Command) error {
	if filePath := cmd.String("file"); filePath != "" {
		if err := processActionsFromFile(cmd, filePath, createAction); err != nil {
			return err
		}
		fmt.Println("Actions added successfully")
		return nil
	}

	if err := createAction(cmd, &state.Action{
		Kind:         cmd.String("kind"),
		Data:         cmd.String("data"),
		ProcessAfter: cmd.Int("process-after"),
		MinInterval:  cmd.Int("min-interval"),
		Comment:      cmd.String("comment"),
	}); err != nil {
		return err
	}

	fmt.Println("Action added successfully")
	return nil
}

func deleteAction(ctx context.Context, cmd *cli.Command) error {
	server := cmd.String("server")
	uuid := cmd.String("uuid")

	if uuid == "" {
		return fmt.Errorf("uuid is required")
	}

	endpointAddress, err := url.JoinPath(server, "api", "action", "store", uuid)
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}

	resp, err := doRequest(cmd, "DELETE", endpointAddress, nil)
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

// testAction is the CLI handler. If --file is provided, reads YAML and tests each action.
// Otherwise tests a single action from flags.
func testAction(ctx context.Context, cmd *cli.Command) error {
	if filePath := cmd.String("file"); filePath != "" {
		if err := processActionsFromFile(cmd, filePath, sendTestAction); err != nil {
			return err
		}
		fmt.Println("Actions tested successfully")
		return nil
	}

	if err := sendTestAction(cmd, &state.Action{
		Kind:         cmd.String("kind"),
		Data:         cmd.String("data"),
		ProcessAfter: cmd.Int("process-after"),
	}); err != nil {
		return err
	}

	fmt.Println("Action tested successfully")
	return nil
}
