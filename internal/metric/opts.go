package metric

import (
	"dmh/internal/state"

	"github.com/prometheus/client_golang/prometheus"
)

type Options struct {
	State    state.StateInterface
	Registry prometheus.Registerer
}
