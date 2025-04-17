package metric

import (
	"fmt"
	"log"
	"time"

	"dmh/internal/state"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	actions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dmh_actions",
		Help: "Number of actions stored in DMMH",
	}, []string{"processed"})
	collectInterval     = 10
	collectIntervalUnit = time.Second
)

type promCollector struct {
	chStop chan bool
	s      state.StateInterface
}

// Initialize register prometheus collectors and start collector.
func Initialize(opts *Options) *promCollector {
	prometheus.MustRegister(actions)

	p := &promCollector{
		chStop: make(chan bool),
		s:      opts.State,
	}

	go p.collect()
	return p
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
					actions.WithLabelValues(fmt.Sprint(k)).Set(float64(v))
				}
			}
		case <-p.chStop:
			return
		}
	}
}
