package identity_test

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/JorisJonkers-dev/identity/contract/principal"

	"github.com/JorisJonkers-dev/go-commons/identity"
)

// keyServer publishes the given JWKS bodies in turn, the last one from then on, and counts its
// fetches and the paths they asked for.
type keyServer struct {
	bodies  [][]byte
	status  int
	fetches atomic.Int32
	path    atomic.Value
}

func (k *keyServer) start(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(k.fetches.Add(1))
		k.path.Store(r.URL.Path)
		if k.status != 0 {
			w.WriteHeader(k.status)
			return
		}
		_, _ = w.Write(k.bodies[min(n, len(k.bodies))-1])
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func publishedKeys(t *testing.T) []byte {
	t.Helper()
	b, err := fs.ReadFile(contract.Files, "vectors/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// clock is a Reader's clock, starting at a vector's time.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func reader(t *testing.T, v vector, keysURL string, c *clock) *identity.Reader {
	t.Helper()
	c.now = v.Now
	r, err := identity.New(identity.Config{Issuer: v.Issuer, ClientID: v.Client, KeysURL: keysURL, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func request(t *testing.T, v vector) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	for k, value := range v.Headers {
		req.Header.Set(k, value)
	}
	return req
}

func TestAReaderNeedsItsIssuerAndItsClient(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  identity.Config
	}{
		{"no Issuer", identity.Config{ClientID: "wiki"}},
		{"no Client", identity.Config{Issuer: "https://auth.example.test"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := identity.New(c.cfg); !errors.Is(err, identity.ErrConfig) {
				t.Fatalf("New = %v", err)
			}
		})
	}
}

func TestAReaderFetchesTheKeysTheIssuerPublishesAtOIDCKeys(t *testing.T) {
	keys := &keyServer{bodies: [][]byte{publishedKeys(t)}}
	issuer := keys.start(t)
	v := vectors(t)["session"]
	r, err := identity.New(identity.Config{Issuer: issuer, ClientID: v.Client})
	if err != nil {
		t.Fatal(err)
	}

	_, _ = r.Read(request(t, v))

	if got, _ := keys.path.Load().(string); got != "/oidc/keys" {
		t.Fatalf("fetched %q", got)
	}
}

func TestAKeyAlreadyFetchedIsNotFetchedAgain(t *testing.T) {
	keys := &keyServer{bodies: [][]byte{publishedKeys(t)}}
	v := vectors(t)["session"]
	r := reader(t, v, keys.start(t), &clock{})

	for range 3 {
		if _, err := r.Read(request(t, v)); err != nil {
			t.Fatal(err)
		}
	}

	if n := keys.fetches.Load(); n != 1 {
		t.Fatalf("%d fetches", n)
	}
}

func TestAnUnknownKeyFetchesTheKeysAgainAtMostOnceAMinute(t *testing.T) {
	keys := &keyServer{bodies: [][]byte{publishedKeys(t)}}
	c := &clock{}
	r := reader(t, vectors(t)["session"], keys.start(t), c)
	stranger := vectors(t)["unknown-key"]
	_, _ = r.Read(request(t, stranger))

	_, _ = r.Read(request(t, stranger))
	if n := keys.fetches.Load(); n != 1 {
		t.Fatalf("%d fetches within the minute", n)
	}
	c.now = c.now.Add(time.Minute)
	_, _ = r.Read(request(t, stranger))
	if n := keys.fetches.Load(); n != 2 {
		t.Fatalf("%d fetches a minute later", n)
	}
}

func TestAKeyTheIssuerStartsPublishingIsReadOnceTheMinuteIsUp(t *testing.T) {
	keys := &keyServer{bodies: [][]byte{[]byte(`{"keys":[]}`), publishedKeys(t)}}
	c := &clock{}
	v := vectors(t)["session"]
	r := reader(t, v, keys.start(t), c)
	// Early enough that the Principal is still alive a minute later.
	c.now = c.now.Add(-40 * time.Second)
	var refused *identity.RefusalError
	if _, err := r.Read(request(t, v)); !errors.As(err, &refused) || refused.Reason != "unknown-key" {
		t.Fatalf("before the Issuer publishes the key = %v", err)
	}

	c.now = c.now.Add(time.Minute)

	if _, err := r.Read(request(t, v)); err != nil {
		t.Fatalf("after = %v", err)
	}
}

func TestKeysThatCannotBeReadAreAnErrorNotARefusal(t *testing.T) {
	unreachable := httptest.NewServer(http.NotFoundHandler())
	unreachable.Close()
	for _, c := range []struct {
		name string
		keys func(t *testing.T) string
	}{
		{"an error status", func(t *testing.T) string { return (&keyServer{status: http.StatusBadGateway}).start(t) }},
		{"a body that is no JWKS", func(t *testing.T) string { return (&keyServer{bodies: [][]byte{[]byte("<html>")}}).start(t) }},
		{"no answer", func(*testing.T) string { return unreachable.URL }},
		{"a URL that is no URL", func(*testing.T) string { return "http://\x7f" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := vectors(t)["session"]
			_, err := reader(t, v, c.keys(t), &clock{}).Read(request(t, v))
			var refused *identity.RefusalError
			if err == nil || errors.As(err, &refused) {
				t.Fatalf("Read = %v", err)
			}
		})
	}
}

func TestMiddlewarePassesThePrincipalOnToTheHandler(t *testing.T) {
	v := vectors(t)["session"]
	r := reader(t, v, issuerKeys(t), &clock{})
	var got identity.Principal
	h := r.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) { got, _ = identity.FromContext(req.Context()) }))

	h.ServeHTTP(httptest.NewRecorder(), request(t, v))

	if got.Subject != v.Principal.Subject || got.SID != v.Principal.SID {
		t.Fatalf("handler saw %+v", got)
	}
}

func TestMiddlewareAnswers401ToARefusedRequest(t *testing.T) {
	v := vectors(t)["spoofed-plain-headers"]
	delete(v.Headers, identity.Header)
	rec := httptest.NewRecorder()

	reader(t, v, issuerKeys(t), &clock{}).Middleware(ok).ServeHTTP(rec, request(t, v))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Middleware = %d", rec.Code)
	}
}

func TestMiddlewareAnswers503WhenTheIssuersKeysCannotBeRead(t *testing.T) {
	v := vectors(t)["session"]
	rec := httptest.NewRecorder()

	reader(t, v, (&keyServer{status: http.StatusBadGateway}).start(t), &clock{}).Middleware(ok).ServeHTTP(rec, request(t, v))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Middleware = %d", rec.Code)
	}
}

func TestARefusalSaysWhy(t *testing.T) {
	if got := (&identity.RefusalError{Reason: "expired"}).Error(); got != "identity: the request's Principal is refused: expired" {
		t.Fatalf("Error = %q", got)
	}
}
