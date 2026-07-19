package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"dmh/internal/crypt"

	"github.com/google/renameio/v2"
)

var (
	// mocks for tests
	atomicWrite = func(path string, data []byte, perm os.FileMode) error {
		return renameio.WriteFile(path, data, perm)
	}
	osChmod     = os.Chmod
	cryptNewAge = crypt.NewAge
	jsonMarshal = json.Marshal
)

// ErrSecretNotReleased is returned when a secret exists but its release time has
// not passed yet.
var ErrSecretNotReleased = errors.New("is not released yet")

// EncryptionMeta stores information about encryption.
type EncryptionMeta struct {
	Kind string `json:"kind"`
}

// Secret stores single private key and information when it can be released.
// Secret will be released after ProcessAfter * hour from LastSeen reported to Vault.
type Secret struct {
	Key            string         `json:"key"`
	ProcessAfter   int            `json:"process_after"`
	EncryptionMeta EncryptionMeta `json:"encryption"`
}

// VaultData stores Secrets for single clientUUID.
type VaultData struct {
	LastSeen time.Time          `json:"last_seen"` // when client was last seen
	Secrets  map[string]*Secret `json:"secrets"`   // stores secrets for client, string index is secret-uuid
}

// Vault internal data.
type Vault struct {
	mtx               sync.RWMutex
	data              map[string]*VaultData // stores vault data string index is client-uuid
	key               string                // Vault uses this key to encrypt all secrets before storing them on disk
	savePath          string                // Vault will dump and loads its state from this file
	secretProcessUnit time.Duration         // time unit used to decide when key should be released.
}

// VaultInterface describes Vault.
type VaultInterface interface {
	UpdateLastSeen(string)
	GetSecret(string, string) (*Secret, error)
	AddSecret(string, string, *Secret) error
	DeleteSecret(string, string) error
}

// New returns new instance of VaultInterface.
// It will try to load saved vault state from disk.
func New(opts *Options) (VaultInterface, error) {
	if opts.SecretProcessUnit < time.Second {
		return nil, fmt.Errorf("SecretProcessUnit must be bigger than second")
	}
	v := &Vault{
		data:              map[string]*VaultData{},
		key:               opts.Key,
		savePath:          opts.SavePath,
		secretProcessUnit: opts.SecretProcessUnit,
	}
	f, err := os.Open(v.savePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("vault file %s does not exist, creating new vault", v.savePath)
			return v, nil
		}
		return nil, fmt.Errorf("unable to open vault file %s: %w", v.savePath, err)
	}
	defer f.Close()

	// Best-effort: chmod can fail on some volumes and must not stop startup.
	if err := osChmod(v.savePath, 0600); err != nil {
		log.Printf("unable to change vault file permissions to 600: %s", err)
	}

	err = json.NewDecoder(f).Decode(&v.data)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// UpdateLastSeen updates when clientUUID was last seen by vault.
func (v *Vault) UpdateLastSeen(clientUUID string) {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.ensureClientUUID(clientUUID)
	v.data[clientUUID].LastSeen = time.Now()
	v.save()
}

// GetSecret returns released secret.
// Secret is considered released when clientUUID was not seen Secret.LastSeen number of hours.
// Secret will be decrypted before returning to client.
func (v *Vault) GetSecret(clientUUID string, secretUUID string) (*Secret, error) {
	v.mtx.RLock()
	defer v.mtx.RUnlock()

	clientData, ok := v.data[clientUUID]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s is missing", clientUUID, secretUUID)
	}

	lastSeen := clientData.LastSeen

	now := time.Now()
	secret, ok := clientData.Secrets[secretUUID]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s is missing", clientUUID, secretUUID)
	}

	if now.Sub(lastSeen) <= time.Duration(secret.ProcessAfter)*v.secretProcessUnit {
		return nil, fmt.Errorf("secret %s/%s %w", clientUUID, secretUUID, ErrSecretNotReleased)
	}

	c, err := cryptNewAge(v.key)
	if err != nil {
		return nil, err
	}

	decryptedKey, err := c.Decrypt(secret.Key)
	if err != nil {
		return nil, err
	}

	s := &Secret{
		Key:            decryptedKey,
		ProcessAfter:   secret.ProcessAfter,
		EncryptionMeta: secret.EncryptionMeta,
	}

	return s, nil
}

// AddSecret adds secret to Vault.
// If secret for clientUUID+secretUUID already exists it will NOT be overridden.
// Secrets will be encrypted with Vault.key before storing.
func (v *Vault) AddSecret(clientUUID string, secretUUID string, secret *Secret) error {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.ensureClientUUID(clientUUID)

	_, ok := v.data[clientUUID].Secrets[secretUUID]
	if ok {
		return fmt.Errorf("secret %s/%s already exists", clientUUID, secretUUID)
	}

	c, err := cryptNewAge(v.key)
	if err != nil {
		return err
	}

	encryptedKey, err := c.Encrypt(secret.Key)
	if err != nil {
		return err
	}

	encryptedSecret := &Secret{
		Key:            encryptedKey,
		ProcessAfter:   secret.ProcessAfter,
		EncryptionMeta: EncryptionMeta{Kind: crypt.EncryptionKind},
	}

	v.data[clientUUID].Secrets[secretUUID] = encryptedSecret
	v.save()
	return nil
}

// DeleteSecret removes secret from Vault.
// Secrets are removed by DMH after processing Action, this way ensuring that data
// cant be recovered after release.
// Secret can be deleted only after releasing.
// Secret is considered released when clientUUID was not seen Secret.LastSeen number of hours.
func (v *Vault) DeleteSecret(clientUUID string, secretUUID string) error {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	clientData, ok := v.data[clientUUID]
	if !ok {
		return fmt.Errorf("secret %s/%s is missing", clientUUID, secretUUID)
	}

	lastSeen := clientData.LastSeen

	now := time.Now()

	secret, ok := clientData.Secrets[secretUUID]
	if !ok {
		return fmt.Errorf("secret %s/%s is missing", clientUUID, secretUUID)
	}

	if now.Sub(lastSeen) <= time.Duration(secret.ProcessAfter)*v.secretProcessUnit {
		return fmt.Errorf("secret %s/%s %w", clientUUID, secretUUID, ErrSecretNotReleased)
	}

	delete(clientData.Secrets, secretUUID)
	v.save()
	return nil
}

// ensureClientUUID ensures proper data structs for clientUUID.
// Caller must hold Vault write lock.
func (v *Vault) ensureClientUUID(clientUUID string) {
	_, ok := v.data[clientUUID]
	if !ok {
		v.data[clientUUID] = &VaultData{
			LastSeen: time.Now(),
			Secrets:  map[string]*Secret{},
		}
	}
}

// save dumps vault to disk.
// save will panic when this is not possible.
// Caller must hold Vault lock.
func (v *Vault) save() {
	data, err := jsonMarshal(v.data)
	if err != nil {
		log.Panicf("unable to encode state: %s", err)
	}
	if err := atomicWrite(v.savePath, data, 0600); err != nil {
		log.Panicf("unable to dump state: %s", err)
	}
}
