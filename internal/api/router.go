package api

import (
	"dmh/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// maxRequestBodyBytes caps request bodies accepted from clients.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// NewRouter creates http router.
func NewRouter(opts *Options) *chi.Mux {
	httpRouter := chi.NewRouter()

	httpRouter.Group(func(r chi.Router) {
		if opts.Auth.Enabled {
			r.Use(auth.SeedIdentity)
		}
		r.Use(middleware.RequestLogger(apiLogFormatter{}))
		r.Use(middleware.CleanPath)
		r.Use(middleware.Recoverer)
		r.Use(middleware.RequestSize(maxRequestBodyBytes))
		r.Use(metricsMiddleware(opts.Metric))
		if opts.Auth.Enabled {
			r.Use(auth.BearerAuthenticator(opts.Auth.Bearer.Tokens))
			r.Use(auth.SignedURLAuthenticator(opts.Auth.SignedURL.Secret))
			r.Use(logIdentity)
			r.Use(auth.Authorizer(opts.Auth.AnonymousScopes))
		}
		r.Get("/ready", healthHandler())
		r.Get("/healthz", healthHandler())
		r.Method("GET", "/metrics", promhttp.Handler())
		if opts.Debug {
			r.Mount("/debug", middleware.Profiler())
		}
		if opts.DMHEnabled {
			r.Route("/alive", func(r chi.Router) {
				r.Get("/", aliveWebHandler())
				r.Post("/", aliveHandler(opts.State, opts.VaultURL, opts.VaultClientUUID, opts.VaultToken))
			})
			r.Route("/api/alive", func(r chi.Router) {
				r.Get("/", aliveHandler(opts.State, opts.VaultURL, opts.VaultClientUUID, opts.VaultToken))
				r.Post("/", aliveHandler(opts.State, opts.VaultURL, opts.VaultClientUUID, opts.VaultToken))
			})
			r.Route("/api/action/test", func(r chi.Router) {
				r.Post("/", testActionHandler(opts.Execute, opts.Auth))
			})
			r.Route("/api/action/store", func(r chi.Router) {
				r.Get("/", listActionsHandler(opts.State))
				r.Post("/", addActionHandler(opts.State, opts.Auth))
				r.Route("/{actionUUID}", func(r chi.Router) {
					r.Get("/", getActionHandler(opts.State))
					r.Delete("/", deleteActionHandler(opts.State))
				})
			})
		}
		if opts.VaultEnabled {
			r.Route("/api/vault/alive", func(r chi.Router) {
				r.Route("/{clientUUID}", func(r chi.Router) {
					r.Get("/", vaultAliveHandler(opts.Vault))
				})
			})
			r.Route("/api/vault/store", func(r chi.Router) {
				r.Route("/{clientUUID}/{secretUUID}", func(r chi.Router) {
					r.Get("/", getVaultSecretHandler(opts.Vault))
					r.Post("/", addVaultSecretHandler(opts.Vault))
					r.Delete("/", deleteVaultSecretHandler(opts.Vault))
				})
			})
		}
	})

	return httpRouter
}
