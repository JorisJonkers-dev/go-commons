package identity_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/JorisJonkers-dev/go-commons/identity"
)

// issuer signs Principals of its own with a throwaway key, for claims no vector carries.
type issuer struct {
	key  *rsa.PrivateKey
	keys string
	now  time.Time
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) }))
	t.Cleanup(srv.Close)
	return &issuer{key: key, keys: srv.URL, now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
}

// read is what a Reader for wiki concludes from a Principal whose payload is payload.
func (i *issuer) read(t *testing.T, payload []byte) (identity.Principal, error) {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: i.key, KeyID: "k"}}, (&jose.SignerOptions{}).WithType(identity.Type))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := jws.CompactSerialize()
	r, err := identity.New(identity.Config{Issuer: "https://auth.example.test", ClientID: "wiki", KeysURL: i.keys, Now: func() time.Time { return i.now }})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set(identity.Header, token)
	return r.Read(req)
}

func (i *issuer) claims(edit func(c map[string]any)) []byte {
	c := map[string]any{
		"iss": "https://auth.example.test", "sub": "ada", "aud": "wiki", "iat": i.now.Unix(), "exp": i.now.Add(time.Minute).Unix(),
		"ver": "1.0", "kind": "user", "email": "ada@example.org", "name": "Ada", "roles": []string{"user"}, "via": "personal-token", "two_factor": false,
	}
	edit(c)
	b, _ := json.Marshal(c)
	return b
}

func TestAnAudienceListingOnlyTheAppsClientIsRead(t *testing.T) {
	i := newIssuer(t)

	if _, err := i.read(t, i.claims(func(c map[string]any) { c["aud"] = []string{"wiki"} })); err != nil {
		t.Fatalf("Read = %v", err)
	}
}

func TestAnAudienceListingAnotherClientBesideTheAppsIsRefused(t *testing.T) {
	i := newIssuer(t)

	_, err := i.read(t, i.claims(func(c map[string]any) { c["aud"] = []string{"wiki", "grafana"} }))

	var refused *identity.RefusalError
	if !errors.As(err, &refused) || refused.Reason != "wrong-audience" {
		t.Fatalf("Read = %v", err)
	}
}

func TestAnAudienceThatIsNeitherAStringNorAListIsRefused(t *testing.T) {
	i := newIssuer(t)

	_, err := i.read(t, i.claims(func(c map[string]any) { c["aud"] = 7 }))

	var refused *identity.RefusalError
	if !errors.As(err, &refused) || refused.Reason != "bad-signature" {
		t.Fatalf("Read = %v", err)
	}
}

func TestASignedPayloadThatIsNoJSONIsRefused(t *testing.T) {
	i := newIssuer(t)

	_, err := i.read(t, []byte("not json"))

	var refused *identity.RefusalError
	if !errors.As(err, &refused) || refused.Reason != "bad-signature" {
		t.Fatalf("Read = %v", err)
	}
}

func TestAPrincipalStatingNoRolesHoldsAnEmptyList(t *testing.T) {
	i := newIssuer(t)

	p, err := i.read(t, i.claims(func(c map[string]any) { delete(c, "roles") }))

	if err != nil || p.Roles == nil || len(p.Roles) != 0 {
		t.Fatalf("Read = %+v, %v", p, err)
	}
}
