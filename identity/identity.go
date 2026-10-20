// Package identity reads who is calling an app from identity's Principal contract
// (github.com/JorisJonkers-dev/identity/contract/principal): the Gate's signed header, verified
// against the Issuer's published keys, never the plain X-Auth-Request-* headers beside it. The
// policy helpers guard an app's routes with the Principal Read found.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// Header is the Gate's signed Principal.
	Header = "X-Identity-Principal"
	// Type is the signed Principal's JWT typ, which no access token carries.
	Type = "identity-principal+jwt"
	// Major is the contract major version this package reads.
	Major = "1"
	// refetchAfter is how soon an unknown key id may fetch the Issuer's keys again.
	refetchAfter = time.Minute
)

// RefusalError is why a request carries no Principal. Reason is one of the contract's refusals:
// missing, wrong-typ, wrong-issuer, wrong-audience, expired, unknown-key, bad-signature,
// unknown-major.
type RefusalError struct{ Reason string }

func (r *RefusalError) Error() string {
	return "identity: the request's Principal is refused: " + r.Reason
}

// ErrConfig is a Config without its Issuer or its Client.
var ErrConfig = errors.New("identity: a Config names its Issuer and its Client")

// Config is where the Principals an app reads come from, and which Client the app is.
type Config struct {
	// Issuer is identity's URL, as each Principal's iss states it.
	Issuer string
	// ClientID is the app's own Client, which each Principal must be signed for.
	ClientID string
	// KeysURL is where the Issuer publishes its keys; Issuer + "/oidc/keys" when empty.
	KeysURL string
	// HTTPClient fetches the keys; http.DefaultClient when nil.
	HTTPClient *http.Client
	// Now is the clock a Principal's expiry is read against; time.Now when nil.
	Now func() time.Time
}

// Reader reads Principals for one Client.
type Reader struct {
	cfg Config

	mu      sync.Mutex
	keys    jose.JSONWebKeySet
	fetched time.Time
}

// New returns a Reader for cfg.
func New(cfg Config) (*Reader, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, ErrConfig
	}
	if cfg.KeysURL == "" {
		cfg.KeysURL = strings.TrimSuffix(cfg.Issuer, "/") + "/oidc/keys"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Reader{cfg: cfg}, nil
}

type claims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	Expiry   int64    `json:"exp"`
	Version  string   `json:"ver"`
	Kind     Kind     `json:"kind"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Via      Via      `json:"via"`
	Actor    *struct {
		Subject string `json:"sub"`
		Name    string `json:"name"`
	} `json:"act"`
	TwoFactor   bool   `json:"two_factor"`
	TwoFactorAt int64  `json:"two_factor_at"`
	SessionID   string `json:"sid"`
}

// audience is a JWT's aud, one Client or a list of them.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	err := json.Unmarshal(b, &many)
	*a = many
	return err
}

// Read is the Principal a request carries, or a *RefusalError saying why it carries none. Any other
// error means the Issuer's keys could not be read.
func (r *Reader) Read(req *http.Request) (Principal, error) {
	token := req.Header.Get(Header)
	if token == "" {
		return Principal{}, &RefusalError{"missing"}
	}
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Principal{}, &RefusalError{"bad-signature"}
	}
	h := jws.Signatures[0].Protected
	if h.ExtraHeaders[jose.HeaderType] != Type {
		return Principal{}, &RefusalError{"wrong-typ"}
	}
	key, err := r.key(req.Context(), h.KeyID)
	if err != nil {
		return Principal{}, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return Principal{}, &RefusalError{"bad-signature"}
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Principal{}, &RefusalError{"bad-signature"}
	}
	if refusal := r.refusal(c); refusal != "" {
		return Principal{}, &RefusalError{refusal}
	}
	return principalOf(c), nil
}

func (r *Reader) refusal(c claims) string {
	major, _, _ := strings.Cut(c.Version, ".")
	switch {
	case major != Major:
		return "unknown-major"
	case c.Issuer != r.cfg.Issuer:
		return "wrong-issuer"
	case len(c.Audience) != 1 || c.Audience[0] != r.cfg.ClientID:
		return "wrong-audience"
	case !r.cfg.Now().Before(time.Unix(c.Expiry, 0)):
		return "expired"
	}
	return ""
}

func principalOf(c claims) Principal {
	p := Principal{
		Subject: c.Subject, Kind: c.Kind, Email: c.Email, Name: c.Name, Roles: c.Roles, Via: c.Via,
		TwoFactor: c.TwoFactor, SID: c.SessionID, Ver: c.Version,
	}
	if p.Roles == nil {
		p.Roles = []string{}
	}
	if c.Actor != nil {
		p.Actor = &Actor{ID: c.Actor.Subject, Name: c.Actor.Name}
	}
	if c.TwoFactorAt != 0 {
		at := time.Unix(c.TwoFactorAt, 0).UTC()
		p.TwoFactorAt = &at
	}
	return p
}

// key is the Issuer's published key with id kid. An id the Reader does not know fetches the keys
// again, at most once a minute, so a rotated key is picked up and a forged id costs little.
func (r *Reader) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k := r.keys.Key(kid); len(k) > 0 {
		return &k[0], nil
	}
	if !r.fetched.IsZero() && r.cfg.Now().Sub(r.fetched) < refetchAfter {
		return nil, &RefusalError{"unknown-key"}
	}
	keys, err := r.fetch(ctx)
	if err != nil {
		return nil, err
	}
	r.keys, r.fetched = keys, r.cfg.Now()
	if k := r.keys.Key(kid); len(k) > 0 {
		return &k[0], nil
	}
	return nil, &RefusalError{"unknown-key"}
}

func (r *Reader) fetch(ctx context.Context) (jose.JSONWebKeySet, error) {
	var keys jose.JSONWebKeySet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.KeysURL, nil)
	if err != nil {
		return keys, err
	}
	res, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return keys, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return keys, fmt.Errorf("identity: the Issuer's keys answered %d", res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(&keys)
	return keys, err
}
