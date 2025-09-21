package metric

import (
	"fmt"
	"log"
	"time"

	"dmh/internal/state"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	collectInterval     = 10
	collectIntervalUnit = time.Second
)

type promCollector struct {
	chStop                 chan bool
	s                      state.StateInterface
	dmhActions             *prometheus.GaugeVec
	dmhMissingSecretsTotal *prometheus.CounterVec
}

// Initialize register prometheus collectors and start collector.
func Initialize(opts *Options) *promCollector {
	dmhActions := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dmh_actions",
		Help: "Number of actions stored in DMH",
	}, []string{"processed"})
	dmhMissingSecretsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dmh_missing_secrets_total",
		Help: "Total number of missing secrets detected in the vault during daily validation",
	}, []string{"action"})
	if opts != nil && opts.Registry != nil {
		opts.Registry.MustRegister(dmhActions)
		opts.Registry.MustRegister(dmhMissingSecretsTotal)
	} else {
		prometheus.MustRegister(dmhActions)
		prometheus.MustRegister(dmhMissingSecretsTotal)
	}

	p := &promCollector{
		chStop:                 make(chan bool),
		s:                      opts.State,
		dmhActions:             dmhActions,
		dmhMissingSecretsTotal: dmhMissingSecretsTotal,
	}

	go p.collect()
	return p
}

// UpdateDMHMissingSecrets increments the dmh_missing_secrets_total counter for a given action uuid by n.
func (p *promCollector) UpdateDMHMissingSecrets(actionUUID string, n int) {
	p.dmhMissingSecretsTotal.WithLabelValues(actionUUID).Add(float64(n))
}

// collect will refresh Prometheus collectors.
func (p *promCollector) collect() {
	log.Printf("starting prometheus collector")
	ticker := time.NewTicker(time.Duration(collectInterval) * collectIntervalUnit)
	for {
		select {
		case <-ticker.C:
			if p.s != nil {
				actionsPerProcessed := map[int]int{0: 0, 1: 0, 2: 0}
				for _, a := range p.s.GetActions() {
					actionsPerProcessed[a.Processed] += 1
				}
				for k, v := range actionsPerProcessed {
					p.dmhActions.WithLabelValues(fmt.Sprint(k)).Set(float64(v))
				}
			}
		case <-p.chStop:
			return
		}
	}
}
