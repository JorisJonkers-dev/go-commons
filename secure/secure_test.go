package secure_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JorisJonkers-dev/go-commons/secure"
)

func served(t *testing.T, p secure.Policy) http.Header {
	t.Helper()
	wrap, err := secure.Headers(p)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The handler can still see and change what was set: the headers are set before it runs.
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Error("the headers were not set before the handler ran")
		}
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status %d: the handler did not answer", rec.Code)
	}
	return rec.Header()
}

func TestEveryResponseCarriesTheFixedHeadersAndThePolicys(t *testing.T) {
	h := served(t, secure.Policy{ContentSecurityPolicy: "default-src 'self'", Permissions: "camera=(self)", HSTS: "max-age=31536000"})
	want := map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"X-Frame-Options":           "DENY",
		"Permissions-Policy":        "camera=(self)",
		"Strict-Transport-Security": "max-age=31536000",
	}
	for name, value := range want {
		if got := h.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestWhatAPolicyLeavesOutGrantsNothingAndSendsNoHSTS(t *testing.T) {
	h := served(t, secure.Policy{ContentSecurityPolicy: "default-src 'none'"})
	if h.Get("Permissions-Policy") != secure.DefaultPermissions || secure.DefaultPermissions != "camera=(), microphone=(), geolocation=()" {
		t.Fatalf("permissions = %q", h.Get("Permissions-Policy"))
	}
	if _, sent := h["Strict-Transport-Security"]; sent {
		t.Fatal("HSTS was sent though the policy names none")
	}
}

func TestAPolicyWithoutAContentSecurityPolicyIsRefused(t *testing.T) {
	if wrap, err := secure.Headers(secure.Policy{HSTS: "max-age=1"}); wrap != nil || !errors.Is(err, secure.ErrNoContentSecurityPolicy) {
		t.Fatalf("Headers = %v, %v", wrap != nil, err)
	}
}
