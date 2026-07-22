package metric

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"dmh/internal/state"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	collectInterval     = 10
	collectIntervalUnit = time.Second
	collectSlowInterval = 12
	collectSlowUnit     = time.Hour
)

type PromCollector struct {
	chStop                 chan bool
	chSlowStop             chan bool
	s                      state.StateInterface
	vaultToken             string
	dmhActions             *prometheus.GaugeVec
	dmhMissingSecretsTotal *prometheus.CounterVec
	dmhActionErrorsTotal   *prometheus.CounterVec
	httpRequestsTotal      *prometheus.CounterVec
	httpRequestDuration    *prometheus.HistogramVec
	authSuccessTotal       *prometheus.CounterVec
	authFailuresTotal      *prometheus.CounterVec
}

// Initialize register prometheus collectors and start collector.
func Initialize(opts *Options) *PromCollector {
	dmhActions := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dmh_actions",
		Help: "Number of actions stored in DMH",
	}, []string{"processed"})
	dmhMissingSecretsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dmh_missing_secrets_total",
		Help: "Total number of missing secrets detected in the vault during daily validation",
	}, []string{"action"})
	dmhActionErrorsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dmh_action_errors_total",
		Help: "Total number of action errors",
	}, []string{"action", "error"})
	httpRequestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dmh_http_requests_total",
		Help: "Total number of HTTP requests, by method and response code",
	}, []string{"method", "code"})
	httpRequestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dmh_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "code"})
	authSuccessTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dmh_auth_success_total",
		Help: "Total number of successful authentications, by credential type",
	}, []string{"type"})
	authFailuresTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dmh_auth_failures_total",
		Help: "Total number of failed authentications, by credential type and reason",
	}, []string{"type", "reason"})
	if opts != nil && opts.Registry != nil {
		opts.Registry.MustRegister(dmhActions)
		opts.Registry.MustRegister(dmhMissingSecretsTotal)
		opts.Registry.MustRegister(dmhActionErrorsTotal)
		opts.Registry.MustRegister(httpRequestsTotal)
		opts.Registry.MustRegister(httpRequestDuration)
		opts.Registry.MustRegister(authSuccessTotal)
		opts.Registry.MustRegister(authFailuresTotal)
	} else {
		prometheus.MustRegister(dmhActions)
		prometheus.MustRegister(dmhMissingSecretsTotal)
		prometheus.MustRegister(dmhActionErrorsTotal)
		prometheus.MustRegister(httpRequestsTotal)
		prometheus.MustRegister(httpRequestDuration)
		prometheus.MustRegister(authSuccessTotal)
		prometheus.MustRegister(authFailuresTotal)
	}

	p := &PromCollector{
		chStop:                 make(chan bool),
		chSlowStop:             make(chan bool),
		s:                      opts.State,
		vaultToken:             opts.VaultToken,
		dmhActions:             dmhActions,
		dmhMissingSecretsTotal: dmhMissingSecretsTotal,
		dmhActionErrorsTotal:   dmhActionErrorsTotal,
		httpRequestsTotal:      httpRequestsTotal,
		httpRequestDuration:    httpRequestDuration,
		authSuccessTotal:       authSuccessTotal,
		authFailuresTotal:      authFailuresTotal,
	}

	go p.collect()
	go p.collectSlow()
	return p
}

// Stop terminates collector goroutines.
func (p *PromCollector) Stop() {
	p.chStop <- true
	p.chSlowStop <- true
}

// UpdateDMHActionErrors increments the dmh_action_errors_total counter for a given action uuid and error label by n.
func (p *PromCollector) UpdateDMHActionErrors(actionUUID, errorLabel string, n int) {
	p.dmhActionErrorsTotal.WithLabelValues(actionUUID, errorLabel).Add(float64(n))
}

// RecordHTTPRequest records an HTTP request and its latency.
func (p *PromCollector) RecordHTTPRequest(method string, code int, d time.Duration) {
	p.httpRequestsTotal.WithLabelValues(method, strconv.Itoa(code)).Inc()
	p.httpRequestDuration.WithLabelValues(method, strconv.Itoa(code)).Observe(d.Seconds())
}

// RecordAuthSuccess records a successful authentication by credential type.
func (p *PromCollector) RecordAuthSuccess(authType string) {
	p.authSuccessTotal.WithLabelValues(authType).Inc()
}

// RecordAuthFailure records a failed authentication by credential type and reason.
func (p *PromCollector) RecordAuthFailure(authType, reason string) {
	p.authFailuresTotal.WithLabelValues(authType, reason).Inc()
}

// collect will refresh Prometheus collectors (regular interval).
func (p *PromCollector) collect() {
	log.Printf("starting prometheus collector")
	collectTicker := time.NewTicker(time.Duration(collectInterval) * collectIntervalUnit)
	for {
		select {
		case <-collectTicker.C:
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

// collectSlow will refresh Prometheus collectors (slow interval).
func (p *PromCollector) collectSlow() {
	log.Printf("starting prometheus slow collector")
	collectSlowTicker := time.NewTicker(time.Duration(collectSlowInterval) * collectSlowUnit)
	for {
		select {
		case <-collectSlowTicker.C:
			if p.s != nil {
				for _, a := range p.s.GetActions() {
					if a.Processed == 2 {
						continue
					}
					secretUrl := a.EncryptionMeta.VaultURL
					if secretUrl == "" {
						p.dmhMissingSecretsTotal.WithLabelValues(a.UUID).Add(1)
						continue
					}

					req, err := http.NewRequest(http.MethodHead, secretUrl, nil)
					if err != nil {
						p.dmhMissingSecretsTotal.WithLabelValues(a.UUID).Add(1)
						continue
					}
					if p.vaultToken != "" {
						req.Header.Set("Authorization", "Bearer "+p.vaultToken)
					}

					client := http.Client{
						Timeout: 3 * time.Second,
					}
					reg, err := client.Do(req)

					if err != nil {
						p.dmhMissingSecretsTotal.WithLabelValues(a.UUID).Add(1)
						continue
					}
					reg.Body.Close()
					if reg.StatusCode != http.StatusOK && reg.StatusCode != http.StatusLocked {
						p.dmhMissingSecretsTotal.WithLabelValues(a.UUID).Add(1)
						continue
					}
				}
			}
		case <-p.chSlowStop:
			return
		}
	}
}
