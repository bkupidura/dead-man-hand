package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/urfave/cli/v3"
)

const defaultServerAddr = "http://localhost:8080"

func main() {
	cmd := &cli.Command{
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

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func getClient(cmd *cli.Command) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
	}
}

func updateAlive(ctx context.Context, cmd *cli.Command) error {
	client := getClient(cmd)
	server := cmd.String("server")
	resp, err := client.Get(fmt.Sprintf("%s/api/alive", server))
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
	resp, err := client.Get(fmt.Sprintf("%s/api/action/store", server))
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

	if data == "" {
		return cli.Exit("Data is required", 1)
	}

	payload := map[string]interface{}{
		"kind":          kind,
		"data":          data,
		"process_after": processAfter,
	}
	if comment != "" {
		payload["comment"] = comment
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	client := getClient(cmd)
	server := cmd.String("server")
	resp, err := client.Post(
		fmt.Sprintf("%s/api/action/store", server),
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
		return cli.Exit("Data is required", 1)
	}

	payload := map[string]interface{}{
		"kind":          kind,
		"data":          data,
		"process_after": 10,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	client := getClient(cmd)
	server := cmd.String("server")
	resp, err := client.Post(
		fmt.Sprintf("%s/api/action/test", server),
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

	req, err := http.NewRequest(
		"DELETE",
		fmt.Sprintf("%s/api/action/store/%s", server, uuid),
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
