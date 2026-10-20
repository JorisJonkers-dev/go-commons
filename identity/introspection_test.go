package identity_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JorisJonkers-dev/go-commons/identity"
)

// identityAnswers answers each introspection with the pinned tool vector's answer until revoked,
// and inactive from then on; it counts the questions.
type identityAnswers struct {
	revoked atomic.Bool
	asked   atomic.Int32
	status  int
}

func (a *identityAnswers) start(t *testing.T) string {
	t.Helper()
	active := pinned[introspectionVector](t, "vectors/introspection")["tool"].Answer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a.asked.Add(1)
		switch {
		case a.status != 0:
			w.WriteHeader(a.status)
		case a.revoked.Load():
			_, _ = w.Write([]byte(`{"active":false}`))
		default:
			_, _ = w.Write(active)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func introspecting(t *testing.T, url string, c *clock) *identity.Reader {
	t.Helper()
	r, err := identity.New(identity.Config{Issuer: "https://auth.example.test", ClientID: "web", ClientSecret: "s3cret", IntrospectURL: url, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func bearer(t *testing.T, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func refusedAs(t *testing.T, err error, reason string) {
	t.Helper()
	var refused *identity.RefusalError
	if !errors.As(err, &refused) || refused.Reason != reason {
		t.Fatalf("Read = %v, want refused %q", err, reason)
	}
}

func TestARevokedOpaqueTokenStopsWorkingWithinThirtySeconds(t *testing.T) {
	answers := &identityAnswers{}
	c := &clock{now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	r := introspecting(t, answers.start(t), c)
	if _, err := r.Read(bearer(t, "idapp_tool")); err != nil {
		t.Fatal(err)
	}

	answers.revoked.Store(true)
	c.now = c.now.Add(29 * time.Second)
	if _, err := r.Read(bearer(t, "idapp_tool")); err != nil {
		t.Fatalf("inside the 30 seconds = %v", err)
	}
	c.now = c.now.Add(time.Second)
	_, err := r.Read(bearer(t, "idapp_tool"))

	refusedAs(t, err, "inactive")
}

func TestAnOpaqueTokenIsAskedAboutOncePerThirtySeconds(t *testing.T) {
	answers := &identityAnswers{}
	r := introspecting(t, answers.start(t), &clock{now: time.Now()})

	for range 5 {
		_, _ = r.Read(bearer(t, "idapp_tool"))
	}

	if n := answers.asked.Load(); n != 1 {
		t.Fatalf("asked %d times", n)
	}
}

func TestAnAppWithoutAClientSecretRefusesAnOpaqueTokenWithoutAsking(t *testing.T) {
	answers := &identityAnswers{}
	r, _ := identity.New(identity.Config{Issuer: "https://auth.example.test", ClientID: "web", IntrospectURL: answers.start(t)})

	_, err := r.Read(bearer(t, "idpat_script"))

	refusedAs(t, err, "inactive")
	if answers.asked.Load() != 0 {
		t.Fatal("asked identity without a secret")
	}
}

func TestIntrospectionThatCannotBeAskedIsAnErrorAndIsAskedAgain(t *testing.T) {
	answers := &identityAnswers{status: http.StatusBadGateway}
	r := introspecting(t, answers.start(t), &clock{now: time.Now()})
	_, first := r.Read(bearer(t, "idapp_tool"))

	answers.status = 0
	_, second := r.Read(bearer(t, "idapp_tool"))

	var refused *identity.RefusalError
	if first == nil || errors.As(first, &refused) || second != nil {
		t.Fatalf("first = %v, second = %v", first, second)
	}
}

func TestAnIntrospectionAnswerThatIsNoJSONIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	t.Cleanup(srv.Close)

	_, err := introspecting(t, srv.URL, &clock{now: time.Now()}).Read(bearer(t, "idapp_tool"))

	var refused *identity.RefusalError
	if err == nil || errors.As(err, &refused) {
		t.Fatalf("Read = %v", err)
	}
}

func TestIntrospectionAtNoAddressIsAnError(t *testing.T) {
	for _, c := range []struct{ name, url string }{
		{"no answer", func() string { s := httptest.NewServer(http.NotFoundHandler()); s.Close(); return s.URL }()},
		{"a URL that is no URL", "http://\x7f"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := introspecting(t, c.url, &clock{now: time.Now()}).Read(bearer(t, "idapp_tool"))
			var refused *identity.RefusalError
			if err == nil || errors.As(err, &refused) {
				t.Fatalf("Read = %v", err)
			}
		})
	}
}

func TestAnIntrospectionURLDefaultsToTheIssuers(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path.Store(req.URL.Path)
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	t.Cleanup(srv.Close)
	r, _ := identity.New(identity.Config{Issuer: srv.URL, ClientID: "web", ClientSecret: "s3cret"})

	_, _ = r.Read(bearer(t, "idpat_script"))

	if got, _ := path.Load().(string); got != "/oidc/introspect" {
		t.Fatalf("asked %q", got)
	}
}

func TestARequestWithoutABearerTokenOrSignedHeaderCarriesNoPrincipal(t *testing.T) {
	r, _ := identity.New(identity.Config{Issuer: "https://auth.example.test", ClientID: "web"})
	for _, c := range []struct{ name, authorization string }{
		{"no Authorization", ""},
		{"another scheme", "Basic dXNlcjpwYXNz"},
		{"an empty bearer token", "Bearer "},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if c.authorization != "" {
				req.Header.Set("Authorization", c.authorization)
			}
			_, err := r.Read(req)
			refusedAs(t, err, "missing")
		})
	}
}
