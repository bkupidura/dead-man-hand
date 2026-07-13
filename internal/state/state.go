package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"dmh/internal/crypt"
	"dmh/internal/vault"

	"github.com/google/renameio/v2"
	"github.com/google/uuid"
)

var (
	// mocks for tests
	cryptNew    = crypt.New
	atomicWrite = func(path string, data []byte, perm os.FileMode) error {
		return renameio.WriteFile(path, data, perm)
	}
	osChmod     = os.Chmod
	jsonMarshal = json.Marshal
	// httpClient is used for the outbound http connections.
	httpClient = &http.Client{Timeout: 30 * time.Second}
)

// Action stores user actions.
// Action is stored only in memory when created via API. It is never saved.
type Action struct {
	Kind         string `json:"kind" yaml:"kind"`                   // kind of action to execute (mail, bulksms, json_post)
	ProcessAfter int    `json:"process_after" yaml:"process_after"` // number of hours (since last seen) before executing action
	MinInterval  int    `json:"min_interval" yaml:"min_interval"`   // number of hours (since last run) before executing action AGAIN. If this is >0 action will be executed forever, use with caution!
	Comment      string `json:"comment" yaml:"comment"`             // comment, it will NOT be encrypted
	Data         string `json:"data" yaml:"data"`                   // json representation of data needed by kind
}

// Validate checks Action fields.
// It is shared by all action creation paths (API, CLI flags, CLI file import).
func (a *Action) Validate() error {
	if a.Data == "" {
		return fmt.Errorf("data is required")
	}
	if a.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	if a.ProcessAfter <= 0 {
		return fmt.Errorf("process_after should be greater than 0")
	}
	if a.MinInterval < 0 {
		return fmt.Errorf("min_interval should be greater or equal 0")
	}
	return nil
}

// EncryptionMeta stores encryption metadata.
type EncryptionMeta struct {
	Kind     string `json:"kind"`      // kind of encryption
	VaultURL string `json:"vault_url"` // remote vault url address
}

// EncryptedAction stores encrypted actions.
// Only those will be saved to disk or exposed with API.
type EncryptedAction struct {
	Action
	UUID           string         `json:"uuid"`       // action random uuid
	Processed      int            `json:"processed"`  // if action was already processed, 0 - not executed, 1 - executed, 2 - executed && priv key deleted from vault
	LastRun        time.Time      `json:"last_run"`   // when action was last executed.
	EncryptionMeta EncryptionMeta `json:"encryption"` // encryption metadata
}

// data stores when user was last seen and encrypted actions.
// data will be dumped to disk in State.savePath location on every change.
// data will be loaded from disk on startup.
type data struct {
	LastSeen time.Time          `json:"last_seen"` // when user was last seen
	Actions  []*EncryptedAction `json:"actions"`   // stores all encrypted actions
}

// StateInterface defines interface used by state component.
type StateInterface interface {
	UpdateLastSeen()
	GetLastSeen() time.Time
	UpdateActionLastRun(string) error
	GetActionLastRun(string) (time.Time, error)
	GetActions() []*EncryptedAction
	GetAction(string) (*EncryptedAction, int)
	AddAction(*Action) error
	DeleteAction(string) error
	MarkActionAsProcessed(string) error
	DecryptAction(string) (*Action, error)
}

// State stores internal state.
type State struct {
	mtx             sync.RWMutex
	data            *data
	vaultURL        string
	vaultClientUUID string
	savePath        string
}

// New returns new instance of State.
// It will load previously saved state if it exists.
func New(opts *Options) (StateInterface, error) {
	state := &State{
		data: &data{
			LastSeen: time.Now(),
			Actions:  []*EncryptedAction{},
		},
		vaultURL:        opts.VaultURL,
		vaultClientUUID: opts.VaultClientUUID,
		savePath:        opts.SavePath,
	}

	f, err := os.Open(state.savePath)
	if err != nil {
		log.Printf("unable to read state file: %s, creating new state", err)
		return state, nil
	}
	defer f.Close()

	// Best-effort: chmod can fail on some volumes and must not stop startup.
	if err := osChmod(state.savePath, 0600); err != nil {
		log.Printf("unable to change state file permissions to 600: %s", err)
	}

	err = json.NewDecoder(f).Decode(state.data)
	if err != nil {
		return nil, err
	}
	return state, nil
}

// UpdateLastSeen updates when user was last seen.
func (s *State) UpdateLastSeen() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.data.LastSeen = time.Now()
	s.save()
}

// GetLastSeen returns when user was last seen.
func (s *State) GetLastSeen() time.Time {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	return s.data.LastSeen
}

// UpdateActionLastRun updates LastRun for action.
func (s *State) UpdateActionLastRun(u string) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	a, _ := s.getAction(u)
	if a == nil {
		return fmt.Errorf("missing action with uuid %s", u)
	}
	a.LastRun = time.Now()
	s.save()
	return nil
}

// GetActionLastRun returns action LastRun.
func (s *State) GetActionLastRun(u string) (time.Time, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	a, _ := s.getAction(u)
	if a == nil {
		return time.Time{}, fmt.Errorf("missing action with uuid %s", u)
	}
	return a.LastRun, nil
}

// AddAction converts Action to EncryptedAction and stores it in State.
// AddAction also uploads private encryption key to remote vault.
func (s *State) AddAction(a *Action) error {
	if err := a.Validate(); err != nil {
		return err
	}

	c, err := cryptNew("")
	if err != nil {
		return err
	}

	encryptedActionUUID := uuid.NewString()

	vaultURL, err := url.JoinPath(s.vaultURL, "api", "vault", "store", s.vaultClientUUID, encryptedActionUUID)
	if err != nil {
		return fmt.Errorf("unable to parse address: %s", err)
	}

	encrypted := &EncryptedAction{
		Action: Action{
			Kind:         a.Kind,
			ProcessAfter: a.ProcessAfter,
			MinInterval:  a.MinInterval,
			Comment:      a.Comment,
		},
		UUID:      encryptedActionUUID,
		Processed: 0,
		EncryptionMeta: EncryptionMeta{
			Kind:     crypt.EncryptionKind,
			VaultURL: vaultURL,
		},
	}

	dataEncrypted, err := c.Encrypt(a.Data)
	if err != nil {
		return err
	}
	encrypted.Action.Data = dataEncrypted

	vaultSecret := &vault.Secret{
		Key:          c.GetPrivateKey(),
		ProcessAfter: a.ProcessAfter,
	}
	vaultSecretJson, err := jsonMarshal(vaultSecret)
	if err != nil {
		return err
	}

	resp, err := httpClient.Post(encrypted.EncryptionMeta.VaultURL, "application/json", bytes.NewBuffer(vaultSecretJson))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unable to publish vault data, status code %d", resp.StatusCode)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.data.Actions = append(s.data.Actions, encrypted)
	s.save()
	return nil
}

// GetActions returns copies of all EncryptedActions.
// Copies are returned so callers can read them without holding State lock.
func (s *State) GetActions() []*EncryptedAction {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	actions := make([]*EncryptedAction, 0, len(s.data.Actions))
	for _, a := range s.data.Actions {
		actionCopy := *a
		actions = append(actions, &actionCopy)
	}
	return actions
}

// getAction returns single EncryptedAction based on uuid.
// Caller must hold State lock.
func (s *State) getAction(u string) (*EncryptedAction, int) {
	for i, a := range s.data.Actions {
		if a.UUID == u {
			return a, i
		}
	}
	return nil, -1
}

// GetAction returns copy of single EncryptedAction based on uuid.
// Copy is returned so callers can read it without holding State lock.
func (s *State) GetAction(u string) (*EncryptedAction, int) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	a, i := s.getAction(u)
	if a == nil {
		return nil, i
	}
	actionCopy := *a
	return &actionCopy, i
}

// DeleteAction deletes actions from State.
func (s *State) DeleteAction(u string) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	a, i := s.getAction(u)
	if a == nil {
		return fmt.Errorf("missing action with uuid %s", u)
	}

	s.data.Actions = append((s.data.Actions)[:i], (s.data.Actions)[i+1:]...)
	s.save()
	return nil

}

// MarkActionAsProcessed sets Processed to 1 or 2.
// 1 - action was executed
// 2 - action was executed and private key was deleted from vault.
func (s *State) MarkActionAsProcessed(u string) error {
	a, err := s.setActionProcessed(u, 1)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodDelete, a.EncryptionMeta.VaultURL, nil)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Deletion was successful or item no longer exist in vault.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("unable to delete vault data, status code %d", resp.StatusCode)
	}

	if _, err := s.setActionProcessed(u, 2); err != nil {
		return err
	}

	return nil
}

// setActionProcessed sets Processed for action and dumps state to disk.
// It returns a copy of the updated action so callers can read it without holding State lock.
func (s *State) setActionProcessed(u string, processed int) (*EncryptedAction, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	a, _ := s.getAction(u)
	if a == nil {
		return nil, fmt.Errorf("missing action with uuid %s", u)
	}
	a.Processed = processed
	s.save()
	actionCopy := *a
	return &actionCopy, nil
}

// DecryptAction decrypts EncryptedAction.
// DecryptAction will fetch private key from remote vault.
func (s *State) DecryptAction(u string) (*Action, error) {
	encryptedAction, _ := s.GetAction(u)
	if encryptedAction == nil {
		return nil, fmt.Errorf("missing action with uuid %s", u)
	}

	resp, err := httpClient.Get(encryptedAction.EncryptionMeta.VaultURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get vault data, status code %d", resp.StatusCode)
	}

	var vaultSecret vault.Secret
	if err := json.NewDecoder(resp.Body).Decode(&vaultSecret); err != nil {
		return nil, err
	}

	c, err := cryptNew(vaultSecret.Key)
	if err != nil {
		return nil, err
	}

	plainTextData, err := c.Decrypt(encryptedAction.Data)
	if err != nil {
		return nil, err
	}

	action := &Action{
		Kind:         encryptedAction.Kind,
		ProcessAfter: encryptedAction.ProcessAfter,
		Comment:      encryptedAction.Comment,
		Data:         plainTextData,
	}

	return action, nil

}

// save dumps state to disk.
// save will panic when this is not possible.
// Caller must hold State lock.
func (s *State) save() {
	data, err := jsonMarshal(s.data)
	if err != nil {
		log.Panicf("unable to encode state: %s", err)
	}
	if err := atomicWrite(s.savePath, data, 0600); err != nil {
		log.Panicf("unable to dump state: %s", err)
	}
}
