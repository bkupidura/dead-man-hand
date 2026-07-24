package api

import (
	_ "embed"
	"net/http"

	"github.com/go-chi/render"
)

// aliveWebPage is a self-contained page allowing humans to confirm they are alive.
//
//go:embed alive.html
var aliveWebPage string

// aliveWebHandler renders static page which allows humans to confirm they are alive.
func aliveWebHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		render.HTML(w, r, aliveWebPage)
	}
}
