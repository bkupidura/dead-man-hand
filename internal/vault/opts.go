package vault

import (
	"time"
)

type Options struct {
	Key               string
	SavePath          string
	SecretProcessUnit time.Duration
}
