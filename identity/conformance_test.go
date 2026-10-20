package identity_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	contract "github.com/JorisJonkers-dev/identity/contract/principal"

	"github.com/JorisJonkers-dev/go-commons/identity"
)

// vector is one of the pinned contract's signed-header conformance vectors.
type vector struct {
	Issuer    string              `json:"issuer"`
	Client    string              `json:"client"`
	Now       time.Time           `json:"now"`
	Headers   map[string]string   `json:"headers"`
	Principal *identity.Principal `json:"principal"`
	Refusal   string              `json:"refusal"`
}

func vectors(t *testing.T) map[string]vector {
	t.Helper()
	paths, err := fs.Glob(contract.Files, "vectors/signed-header/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no vectors: %v", err)
	}
	out := map[string]vector{}
	for _, p := range paths {
		raw, _ := fs.ReadFile(contract.Files, p)
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[strings.TrimSuffix(path.Base(p), ".json")] = v
	}
	return out
}

// issuerKeys serves the pinned contract's JWKS, as the Issuer publishes its keys.
func issuerKeys(t *testing.T) string {
	t.Helper()
	jwks, err := fs.ReadFile(contract.Files, "vectors/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

func encoded(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEveryPinnedVectorReadsAsTheContractSays(t *testing.T) {
	keys := issuerKeys(t)
	for name, v := range vectors(t) {
		t.Run(name, func(t *testing.T) {
			r, err := identity.New(identity.Config{Issuer: v.Issuer, ClientID: v.Client, KeysURL: keys, Now: func() time.Time { return v.Now }})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			for k, value := range v.Headers {
				req.Header.Set(k, value)
			}

			p, err := r.Read(req)

			var refused *identity.RefusalError
			switch {
			case v.Refusal != "":
				if !errors.As(err, &refused) || refused.Reason != v.Refusal {
					t.Fatalf("Read = %+v, %v; want refused %q", p, err, v.Refusal)
				}
			case err != nil:
				t.Fatalf("Read = %v", err)
			case encoded(t, p) != encoded(t, v.Principal):
				t.Fatalf("Read = %s\nwant %s", encoded(t, p), encoded(t, v.Principal))
			}
		})
	}
}

// tokenVector is one of the pinned contract's access-token vectors.
type tokenVector struct {
	Issuer    string              `json:"issuer"`
	Client    string              `json:"client"`
	Now       time.Time           `json:"now"`
	Token     string              `json:"token"`
	Principal *identity.Principal `json:"principal"`
	Refusal   string              `json:"refusal"`
}

// introspectionVector is one of the pinned contract's introspection vectors.
type introspectionVector struct {
	Client    string              `json:"client"`
	Answer    json.RawMessage     `json:"answer"`
	Principal *identity.Principal `json:"principal"`
	Refusal   string              `json:"refusal"`
}

func pinned[T any](t *testing.T, dir string) map[string]T {
	t.Helper()
	paths, err := fs.Glob(contract.Files, dir+"/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no vectors in %s: %v", dir, err)
	}
	out := map[string]T{}
	for _, p := range paths {
		raw, _ := fs.ReadFile(contract.Files, p)
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[strings.TrimSuffix(path.Base(p), ".json")] = v
	}
	return out
}

func readAs(t *testing.T, r *identity.Reader, req *http.Request, principal *identity.Principal, refusal string) {
	t.Helper()
	p, err := r.Read(req)
	var refused *identity.RefusalError
	switch {
	case refusal != "":
		if !errors.As(err, &refused) || refused.Reason != refusal {
			t.Fatalf("Read = %+v, %v; want refused %q", p, err, refusal)
		}
	case err != nil:
		t.Fatalf("Read = %v", err)
	case encoded(t, p) != encoded(t, principal):
		t.Fatalf("Read = %s\nwant %s", encoded(t, p), encoded(t, principal))
	}
}

func TestEveryPinnedAccessTokenVectorReadsAsTheContractSays(t *testing.T) {
	keys := issuerKeys(t)
	for name, v := range pinned[tokenVector](t, "vectors/access-token") {
		t.Run(name, func(t *testing.T) {
			r, err := identity.New(identity.Config{Issuer: v.Issuer, ClientID: v.Client, KeysURL: keys, Now: func() time.Time { return v.Now }})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+v.Token)

			readAs(t, r, req, v.Principal, v.Refusal)
		})
	}
}

func TestEveryPinnedIntrospectionVectorReadsAsTheContractSays(t *testing.T) {
	for name, v := range pinned[introspectionVector](t, "vectors/introspection") {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if id, secret, ok := req.BasicAuth(); !ok || id != v.Client || secret != "s3cret" || req.PostFormValue("token") != "opaque" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = w.Write(v.Answer)
			}))
			t.Cleanup(srv.Close)
			r, err := identity.New(identity.Config{Issuer: "https://auth.example.test", ClientID: v.Client, ClientSecret: "s3cret", IntrospectURL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer opaque")

			readAs(t, r, req, v.Principal, v.Refusal)
		})
	}
}

func TestAnAccessTokenPresentedAsTheSignedHeaderIsRefusedByTyp(t *testing.T) {
	v := pinned[tokenVector](t, "vectors/access-token")["session"]
	r, _ := identity.New(identity.Config{Issuer: v.Issuer, ClientID: v.Client, KeysURL: issuerKeys(t), Now: func() time.Time { return v.Now }})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set(identity.Header, v.Token)

	readAs(t, r, req, nil, "wrong-typ")
}

func TestASignedHeaderPresentedAsABearerTokenIsRefusedByTyp(t *testing.T) {
	v := vectors(t)["session"]
	r, _ := identity.New(identity.Config{Issuer: v.Issuer, ClientID: v.Client, KeysURL: issuerKeys(t), Now: func() time.Time { return v.Now }})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+v.Headers[identity.Header])

	readAs(t, r, req, nil, "wrong-typ")
}
