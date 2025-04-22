package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"dmh/internal/crypt"
	"dmh/internal/vault"

	"github.com/google/uuid"
)

var (
	// mocks for tests
	cryptNew    = crypt.New
	osCreate    = os.Create
	jsonMarshal = json.Marshal
)

// Action stores user actions.
// Action is stored only in memory when created via API. It is never saved.
type Action struct {
	Kind         string `json:"kind"`          // kind of action to execute (mail, bulksms, json_post)
	ProcessAfter int    `json:"process_after"` // number of hours (since last seen) before executing action
	MinInterval  int    `json:"min_interval"`  // number of hours (since last run) before executing action AGAIN. If this is >0 action will be executed forever, use with caution!
	Comment      string `json:"comment"`       // comment, it will NOT be encrypted
	Data         string `json:"data"`          // json representation of data needed by kind
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

	err = json.NewDecoder(f).Decode(state.data)
	if err != nil {
		return nil, err
	}
	return state, nil
}

// UpdateLastSeen updates when user was last seen.
func (s *State) UpdateLastSeen() {
	s.data.LastSeen = time.Now()
	s.save()
}

// GetLastSeen returns when user was last seen.
func (s *State) GetLastSeen() time.Time {
	return s.data.LastSeen
}

// UpdateActionLastRun updates LastRun for action.
func (s *State) UpdateActionLastRun(u string) error {
	a, _ := s.GetAction(u)
	if a == nil {
		return fmt.Errorf("missing action with uuid %s", u)
	}
	a.LastRun = time.Now()
	s.save()
	return nil
}

// GetActionLastRun returns action LastRun.
func (s *State) GetActionLastRun(u string) (time.Time, error) {
	a, _ := s.GetAction(u)
	if a == nil {
		return time.Time{}, fmt.Errorf("missing action with uuid %s", u)
	}
	return a.LastRun, nil
}

// AddAction converts Action to EncryptedAction and stores it in State.
// AddAction also uploads private encryption key to remote vault.
func (s *State) AddAction(a *Action) error {
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

	resp, err := http.Post(encrypted.EncryptionMeta.VaultURL, "application/json", bytes.NewBuffer(vaultSecretJson))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unable to publish vault data, status code %d", resp.StatusCode)
	}

	s.data.Actions = append(s.data.Actions, encrypted)
	s.save()
	return nil
}

// GetActions returns all EncryptedActions.
func (s *State) GetActions() []*EncryptedAction {
	return s.data.Actions
}

// GetAction returns single EncryptedAction based on uuid.
func (s *State) GetAction(u string) (*EncryptedAction, int) {
	for i, a := range s.data.Actions {
		if a.UUID == u {
			return a, i
		}
	}
	return nil, -1
}

// DeleteAction deletes actions from State.
func (s *State) DeleteAction(u string) error {
	a, i := s.GetAction(u)
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
	a, i := s.GetAction(u)
	if a == nil {
		return fmt.Errorf("missing action with uuid %s", u)
	}

	s.data.Actions[i].Processed = 1
	s.save()

	req, err := http.NewRequest(http.MethodDelete, a.EncryptionMeta.VaultURL, nil)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Deletion was successfull or item no longer exist in vault.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("unable to delete vault data, status code %d", resp.StatusCode)
	}

	s.data.Actions[i].Processed = 2
	s.save()

	return nil
}

// DecryptAction decrypts EncryptedAction.
// DecryptAction will fetch private key from remote vault.
func (s *State) DecryptAction(u string) (*Action, error) {
	encryptedAction, _ := s.GetAction(u)
	if encryptedAction == nil {
		return nil, fmt.Errorf("missing action with uuid %s", u)
	}

	resp, err := http.Get(encryptedAction.EncryptionMeta.VaultURL)
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
func (s *State) save() {
	f, err := osCreate(s.savePath)
	if err != nil {
		log.Panicf("unable to dump state: %s", err)
	}
	defer f.Close()

	err = json.NewEncoder(f).Encode(s.data)
	if err != nil {
		log.Panicf("unable to encode state: %s", err)
	}
}
