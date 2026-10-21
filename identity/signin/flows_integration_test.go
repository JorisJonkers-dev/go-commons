//go:build integration

package signin_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/JorisJonkers-dev/identity/contract/flows"

	"github.com/JorisJonkers-dev/go-commons/identity/signin"
)

// TestTheKitPassesThePrincipalContractsFlowSuite runs the flow suite against a minimal app on the
// kit: README.md's routes in contract/flows, and nothing else.
func TestTheKitPassesThePrincipalContractsFlowSuite(t *testing.T) {
	flows.Run(t, flows.ImagesFromEnv(), func(t *testing.T, env flows.Env) {
		kit, err := signin.New(t.Context(), signin.Config{Issuer: env.Issuer, ClientID: env.ClientID, BaseURL: env.BaseURL})
		if err != nil {
			t.Fatal(err)
		}
		me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := kit.Principal(r)
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(p)
		})
		mux := http.NewServeMux()
		mux.Handle("/", kit.Handler())
		mux.Handle("GET /me", me)
		mux.HandleFunc("GET /fresh", func(w http.ResponseWriter, r *http.Request) {
			minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
			kit.RequireRecentTwoFactor(minutes)(me).ServeHTTP(w, r)
		})
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", env.Port))
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: mux} //nolint:gosec // a test server
		go func() { _ = srv.Serve(l) }()
		t.Cleanup(func() { _ = srv.Close() })
	})
}
