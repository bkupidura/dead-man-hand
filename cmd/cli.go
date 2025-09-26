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

	"github.com/urfave/cli/v3"
)

var (
	// mocks for tests
	newRequest  = http.NewRequest
	jsonMarshal = json.Marshal
)

const defaultServerAddr = "http://127.0.0.1:8080"

var getClient = func(cmd *cli.Command) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
	}
}

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
						Usage: "Add a new action",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "data",
								Aliases:  []string{"d"},
								Usage:    "Action data (json formatted)",
								Required: true,
							},
							&cli.StringFlag{
								Name:  "comment",
								Usage: "Action comment (will be stored unencrypted)",
							},
							&cli.StringFlag{
								Name:     "kind",
								Aliases:  []string{"k"},
								Usage:    "Action kind",
								Required: true,
							},
							&cli.IntFlag{
								Name:     "process-after",
								Aliases:  []string{"p"},
								Usage:    "Process action after <param> hours from last seen",
								Required: true,
								Value:    12,
							},
							&cli.IntFlag{
								Name:    "min-interval",
								Aliases: []string{"i"},
								Usage:   "Process action after <param> hours from last run. If min-interval > 0, action will be run FOREVER and NOT ONCE. USE WITH CAUTION!",
								Value:   0,
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

func addAction(ctx context.Context, cmd *cli.Command) error {
	data := cmd.String("data")
	comment := cmd.String("comment")
	kind := cmd.String("kind")
	processAfter := cmd.Int("process-after")
	minInterval := cmd.Int("min-interval")

	if data == "" {
		return fmt.Errorf("data is required")
	}
	if kind == "" {
		return fmt.Errorf("kind is required")
	}

	payload := map[string]interface{}{
		"kind":          kind,
		"data":          data,
		"process_after": processAfter,
		"min_interval":  minInterval,
	}
	if comment != "" {
		payload["comment"] = comment
	}

	jsonData, err := jsonMarshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	client := getClient(cmd)
	server := cmd.String("server")
	endpointAddress, err := url.JoinPath(server, "api", "action", "store")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}
	resp, err := client.Post(
		endpointAddress,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("Action added successfully")
	return nil
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

	payload := map[string]interface{}{
		"kind":          kind,
		"data":          data,
		"process_after": 10,
	}

	jsonData, err := jsonMarshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	client := getClient(cmd)
	server := cmd.String("server")
	endpointAddress, err := url.JoinPath(server, "api", "action", "test")
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}
	resp, err := client.Post(
		endpointAddress,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
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

	req, err := newRequest(
		"DELETE",
		endpointAddress,
		nil,
	)
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
