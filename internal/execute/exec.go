package execute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"dmh/internal/state"
)

const (
	defaultMaxExecTimeoutSeconds = 300
	maxExecOutputBytes           = 1 << 20 // 1 MiB
)

// ExecConfig configures which absolute paths (or directory prefixes, ending in "/") the exec
// plugin may run. An empty AllowedPaths with a non-empty DeniedPaths allows everything except
// what's denied; a non-empty AllowedPaths restricts to just that list, minus DeniedPaths
// (deny wins on conflict). Both lists empty allows everything.
type ExecConfig struct {
	AllowedPaths []string `koanf:"allowed_paths"`
	DeniedPaths  []string `koanf:"denied_paths"`
	MaxTimeout   int      `koanf:"max_timeout"` // seconds, defaults to defaultMaxExecTimeoutSeconds
}

// Validate checks ExecConfig fields.
func (c *ExecConfig) Validate() error {
	for _, p := range c.AllowedPaths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("allowed_paths entries must be absolute paths")
		}
	}
	for _, p := range c.DeniedPaths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("denied_paths entries must be absolute paths")
		}
	}
	if len(c.AllowedPaths) == 0 && len(c.DeniedPaths) == 0 {
		log.Printf("execute.plugin.exec has no allowed_paths or denied_paths configured, allowing all paths, check https://github.com/bkupidura/dead-man-hand/wiki/Security#restrict-the-exec-plugin-to-specific-paths")
	}
	if c.MaxTimeout <= 0 {
		c.MaxTimeout = defaultMaxExecTimeoutSeconds
	}
	return nil
}

type ExecuteExec struct {
	Path        string            `json:"path"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	InheritEnv  bool              `json:"inherit_env"`
	Timeout     int               `json:"timeout"`
	ExitCode    []int             `json:"exit_code"`
	OutputRegex string            `json:"output_regex"`
	config      ExecConfig
}

// execOutputBuffer caps how many bytes of stdout/stderr are retained; writes beyond the cap
// are dropped, not buffered, so a runaway process can't grow this without bound.
type execOutputBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (w *execOutputBuffer) Write(p []byte) (int, error) {
	if remaining := w.limit - w.buf.Len(); remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		w.buf.Write(p[:remaining])
	}
	return len(p), nil
}

// Run executes Path with Args, no shell involved.
func (d *ExecuteExec) Run() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(d.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, d.Path, d.Args...)
	cmd.Dir = os.TempDir()

	if d.InheritEnv {
		cmd.Env = os.Environ()
	} else {
		cmd.Env = []string{}
	}
	for k, v := range d.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	output := &execOutputBuffer{limit: maxExecOutputBytes}
	cmd.Stdout = output
	cmd.Stderr = output

	runErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("exec %s timed out after %ds", d.Path, d.Timeout)
	}

	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return fmt.Errorf("unable to run %s: %w", d.Path, runErr)
	}

	exitCode := cmd.ProcessState.ExitCode()
	if !slices.Contains(d.ExitCode, exitCode) {
		return fmt.Errorf("exec %s exited with unexpected code %d", d.Path, exitCode)
	}

	if d.OutputRegex != "" {
		re, err := regexp.Compile(d.OutputRegex)
		if err != nil {
			return fmt.Errorf("output_regex is not a valid regex: %w", err)
		}
		if !re.Match(output.buf.Bytes()) {
			return fmt.Errorf("exec %s output did not match output_regex", d.Path)
		}
	}

	return nil
}

// populate parses Action.Data and validates the resulting action.
func (d *ExecuteExec) populate(a *state.Action) error {
	err := json.Unmarshal([]byte(a.Data), &d)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(d.Path, "/") {
		return fmt.Errorf("path must be an absolute path")
	}
	d.Path = filepath.Clean(d.Path)
	if !pathIsPermitted(d.config, d.Path) {
		return fmt.Errorf("path %s is not permitted by execute.plugin.exec config", d.Path)
	}
	if d.Timeout <= 0 {
		return fmt.Errorf("timeout must be provided")
	}
	if d.Timeout > d.config.MaxTimeout {
		return fmt.Errorf("timeout must not exceed %d seconds", d.config.MaxTimeout)
	}
	if len(d.ExitCode) == 0 {
		return fmt.Errorf("exit_code must be provided")
	}
	if d.OutputRegex != "" {
		if _, err := regexp.Compile(d.OutputRegex); err != nil {
			return fmt.Errorf("output_regex is not a valid regex: %w", err)
		}
	}
	return nil
}

// pathIsPermitted applies ExecConfig's allow/deny lists to path, deny wins on conflict.
func pathIsPermitted(c ExecConfig, path string) bool {
	if pathMatches(c.DeniedPaths, path) {
		return false
	}
	if len(c.AllowedPaths) == 0 {
		return true
	}
	return pathMatches(c.AllowedPaths, path)
}

// pathMatches reports whether path equals an entry exactly, or falls under a directory-prefix
// entry (an entry ending in "/").
func pathMatches(entries []string, path string) bool {
	for _, entry := range entries {
		if entry == path {
			return true
		}
		if strings.HasSuffix(entry, "/") && strings.HasPrefix(path, entry) {
			return true
		}
	}
	return false
}

// populateConfig populates config from Executor config and validates it.
func (d *ExecuteExec) populateConfig(e *Execute) error {
	d.config = e.execConf
	return d.config.Validate()
}
