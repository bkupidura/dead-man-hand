package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRouter creates http router.
func NewRouter(opts *Options) *chi.Mux {
	httpRouter := chi.NewRouter()

	httpRouter.Group(func(r chi.Router) {
		r.Use(middleware.CleanPath)
		r.Use(middleware.Recoverer)
		r.Get("/ready", healthHandler())
		r.Get("/healthz", healthHandler())
		r.Method("GET", "/metrics", promhttp.Handler())
		r.Mount("/debug", middleware.Profiler())
		if opts.DMHEnabled {
			r.Route("/api/alive", func(r chi.Router) {
				r.Get("/", aliveHandler(opts.State, opts.VaultURL, opts.VaultClientUUID))
				r.Post("/", aliveHandler(opts.State, opts.VaultURL, opts.VaultClientUUID))
			})
			r.Route("/api/action/test", func(r chi.Router) {
				r.Post("/", testActionHandler(opts.Execute))
			})
			r.Route("/api/action/store", func(r chi.Router) {
				r.Get("/", listActionsHandler(opts.State))
				r.Post("/", addActionHandler(opts.State))
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
