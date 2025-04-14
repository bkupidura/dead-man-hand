package api

import (
	"fmt"
	"log"
	"net/http"

	"dmh/internal/execute"
	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// ErrResponse is generic error code struct.
type ErrResponse struct {
	Err            error  `json:"-"`               // low-level runtime error
	HTTPStatusCode int    `json:"-"`               // http response status code
	StatusText     string `json:"status"`          // user-level status message
	ErrorText      string `json:"error,omitempty"` // application-level error message, for debugging
}

// Render returns rendered error response.
func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

// ErrInvalidRequests returns BadRequest.
func ErrInvalidRequest(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: http.StatusBadRequest,
		StatusText:     "Invalid request.",
		ErrorText:      err.Error(),
	}
}

// ErrInternal returns InternalServerError.
func ErrInternal(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: http.StatusInternalServerError,
		StatusText:     "Internal error.",
	}
}

// ErrNotFound returns NotFound.
func ErrNotFound(err error) render.Renderer {
	return &ErrResponse{
		HTTPStatusCode: http.StatusNotFound,
		StatusText:     "Resource not found.",
	}
}

// OkResponse is generic ok code struct.
type OkResponse struct {
	HTTPStatusCode int `json:"-"`
}

// Render returns rendered ok response.
func (o *OkResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, o.HTTPStatusCode)
	return nil
}

// healthHandler is used by /ready and /healthz endpoints.
func healthHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusOK})
	}
}

// aliveHandler updates State.LastSeen.
// aliveHandler also updates LastSeen in vault.
func aliveHandler(s state.StateInterface, vaultURL string, vaultClientUUID string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		s.UpdateLastSeen()

		resp, err := http.Get(fmt.Sprintf("%s/api/vault/alive/%s", vaultURL, vaultClientUUID))
		if err != nil {
			render.Render(w, r, ErrInternal(nil))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			render.Render(w, r, ErrInternal(nil))
			return
		}

		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusOK})
	}
}

// vaultAliveHandler updates Vault LastSeen.
func vaultAliveHandler(v vault.VaultInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		paramClientUUID := chi.URLParam(r, "clientUUID")
		if paramClientUUID == "" {
			render.Render(w, r, ErrNotFound(nil))
			return
		}
		v.UpdateLastSeen(paramClientUUID)
		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusOK})
	}
}

// testActionHandler allow to execute action for test.
func testActionHandler(e execute.ExecuteInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		request := &addTestActionRequest{}
		if err := render.Bind(r, request); err != nil {
			render.Render(w, r, ErrInvalidRequest(err))
			return
		}

		a := &state.Action{
			Kind:         request.Kind,
			Data:         request.Data,
			ProcessAfter: request.ProcessAfter,
		}
		if err := e.Run(a); err != nil {
			render.Render(w, r, ErrInvalidRequest(err))
			return
		}

		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusOK})
	}
}

// listActionsHandler return all actions.
func listActionsHandler(s state.StateInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, s.GetActions())
	}
}

// addATestActionRequest describes user requests to add new action or test action.
type addTestActionRequest struct {
	Kind         string `json:"kind"`
	Data         string `json:"data"`
	Comment      string `json:"comment"`
	ProcessAfter int    `json:"process_after"`
}

// Bind validates addTestActionRequest.
func (req *addTestActionRequest) Bind(r *http.Request) error {
	a := &state.Action{
		Kind:         req.Kind,
		Comment:      req.Comment,
		ProcessAfter: req.ProcessAfter,
		Data:         req.Data,
	}
	if _, err := execute.UnmarshalActionData(a); err != nil {
		return err
	}

	if req.ProcessAfter <= 0 {
		return fmt.Errorf("process_after should be greater than 0")
	}
	return nil
}

// addActionhandler adds new action to State.
func addActionHandler(s state.StateInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		request := &addTestActionRequest{}
		if err := render.Bind(r, request); err != nil {
			render.Render(w, r, ErrInvalidRequest(err))
			return
		}

		a := &state.Action{
			Kind:         request.Kind,
			Data:         request.Data,
			ProcessAfter: request.ProcessAfter,
			Comment:      request.Comment,
		}

		if err := s.AddAction(a); err != nil {
			render.Render(w, r, ErrInternal(nil))
			return
		}

		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusCreated})
	}
}

// addVaultSecretRequest describes user requests to add new vault secret.
type addVaultSecretRequest struct {
	Key          string `json:"key"`
	ProcessAfter int    `json:"process_after"`
}

// Bind validates addVaultSecretRequest.
func (req *addVaultSecretRequest) Bind(r *http.Request) error {
	if req.Key == "" {
		return fmt.Errorf("key must be provided")
	}

	if req.ProcessAfter <= 0 {
		return fmt.Errorf("process_after should be greater than 0")
	}
	return nil
}

// addVaultSecretHandler adds new secret to Vault.
func addVaultSecretHandler(v vault.VaultInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		paramClientUUID := chi.URLParam(r, "clientUUID")
		paramSecretUUID := chi.URLParam(r, "secretUUID")

		if paramClientUUID == "" || paramSecretUUID == "" {
			render.Render(w, r, ErrInvalidRequest(fmt.Errorf("provide valid clientUUID or secretUUID")))
			return
		}

		request := &addVaultSecretRequest{}
		if err := render.Bind(r, request); err != nil {
			render.Render(w, r, ErrInvalidRequest(err))
			return
		}

		secret := &vault.Secret{
			Key:          request.Key,
			ProcessAfter: request.ProcessAfter,
		}

		if err := v.AddSecret(paramClientUUID, paramSecretUUID, secret); err != nil {
			log.Printf("unable to add secret: %s", err)
			render.Render(w, r, ErrInvalidRequest(fmt.Errorf("unable to add secret")))
			return
		}

		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusCreated})
	}
}

// getActionHandler returns single action from State based on UUID.
func getActionHandler(s state.StateInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		paramActionUUID := chi.URLParam(r, "actionUUID")
		a, _ := s.GetAction(paramActionUUID)
		if a != nil {
			render.JSON(w, r, a)
			return
		}
		render.Render(w, r, ErrNotFound(nil))
	}
}

// getVaultSecretHandler returns secret from Vault.
func getVaultSecretHandler(v vault.VaultInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		paramClientUUID := chi.URLParam(r, "clientUUID")
		paramSecretUUID := chi.URLParam(r, "secretUUID")
		s, err := v.GetSecret(paramClientUUID, paramSecretUUID)
		if err != nil {
			log.Printf("unable to return vault secret: %s", err)
			render.Render(w, r, ErrNotFound(nil))
			return
		}
		render.JSON(w, r, s)
	}
}

// deleteActionHandler deletes single action from State based on UUID.
func deleteActionHandler(s state.StateInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		paramActionUUID := chi.URLParam(r, "actionUUID")
		err := s.DeleteAction(paramActionUUID)
		if err != nil {
			render.Render(w, r, ErrNotFound(nil))
			return
		}
		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusOK})
	}
}

// deleteVaultSecretHandler deletes secret from Vault.
func deleteVaultSecretHandler(v vault.VaultInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		paramClientUUID := chi.URLParam(r, "clientUUID")
		paramSecretUUID := chi.URLParam(r, "secretUUID")

		err := v.DeleteSecret(paramClientUUID, paramSecretUUID)
		if err != nil {
			log.Printf("unable to delete secret: %s", err)
			render.Render(w, r, ErrNotFound(nil))
			return
		}
		render.Render(w, r, &OkResponse{HTTPStatusCode: http.StatusOK})
	}
}
