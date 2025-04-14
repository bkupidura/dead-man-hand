package crypt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
)

var (
	EncryptionKind = "X25519"
	// mocks for tests
	ageGenerateX25519Identity = age.GenerateX25519Identity
	ageEncrypt                = age.Encrypt
	ageDecrypt                = age.Decrypt
	ioWriteString             = io.WriteString
	ioCopy                    = io.Copy
)

// CryptInterface implement Crypt.
type CryptInterface interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
	GetPrivateKey() string
}

// Crypt stores age encryption framework.
type Crypt struct {
	identity *age.X25519Identity
}

// New returns new instance of age.
// If key is provided, instance will be created from key.
func New(key string) (CryptInterface, error) {
	var identity *age.X25519Identity
	var err error
	if key == "" {
		identity, err = ageGenerateX25519Identity()
	} else {
		identity, err = age.ParseX25519Identity(key)
	}
	if err != nil {
		return nil, err
	}

	return &Crypt{
		identity: identity,
	}, nil
}

// Encrypt encrypts input data.
// Encrypt will return encrypted data and error.
// Encrypted data is base64 decoded.
func (c *Crypt) Encrypt(data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("empty data")
	}
	out := &bytes.Buffer{}
	w, err := ageEncrypt(out, c.identity.Recipient())
	if err != nil {
		return "", err
	}
	if _, err := ioWriteString(w, data); err != nil {
		return "", err
	}
	w.Close()
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

// Decrypt decrypts input data.
// Decrypt will return plain text data and error.
// Decrypt expect that input data is base64 encoded.
func (c *Crypt) Decrypt(data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("empty data")
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	r, err := ageDecrypt(bytes.NewReader(decodedBytes), c.identity)
	if err != nil {
		return "", err
	}

	out := &bytes.Buffer{}
	if _, err := ioCopy(out, r); err != nil {
		return "", err
	}
	return out.String(), nil
}

// GetPrivateKey returns age private key.
func (c *Crypt) GetPrivateKey() string {
	return c.identity.String()
}
