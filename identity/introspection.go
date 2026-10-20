package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	// answerLifetime is how long an introspection answer is kept, so a revoked token stops working
	// within it.
	answerLifetime = 30 * time.Second
	// maxAnswers bounds the answers kept; past it they are all dropped.
	maxAnswers = 10_000
)

// answer is what identity answered about an opaque token, kept until until.
type answer struct {
	principal Principal
	err       error
	until     time.Time
}

// introspected is the Principal identity answers for an opaque token, a Personal Token or a
// Connected App's, asked at most once per answerLifetime.
func (r *Reader) introspected(ctx context.Context, token string) (Principal, error) {
	if r.cfg.ClientSecret == "" {
		return Principal{}, &RefusalError{"inactive"}
	}
	sum := sha256.Sum256([]byte(token))
	key := string(sum[:])
	now := r.cfg.Now()
	r.answersMu.Lock()
	a, ok := r.answers[key]
	r.answersMu.Unlock()
	if ok && now.Before(a.until) {
		return a.principal, a.err
	}
	c, err := r.ask(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	p, err := r.answered(c)
	r.answersMu.Lock()
	if len(r.answers) >= maxAnswers {
		r.answers = map[string]answer{}
	}
	r.answers[key] = answer{principal: p, err: err, until: now.Add(answerLifetime)}
	r.answersMu.Unlock()
	return p, err
}

// answered is the Principal an introspection answer states for this Reader's Client.
func (r *Reader) answered(c claims) (Principal, error) {
	major, _, _ := strings.Cut(c.Version, ".")
	switch {
	case c.Active == nil || !*c.Active:
		return Principal{}, &RefusalError{"inactive"}
	case major != Major:
		return Principal{}, &RefusalError{"unknown-major"}
	case c.ClientID != r.cfg.ClientID || !slices.Equal(c.Audience, audience{r.cfg.ClientID}):
		return Principal{}, &RefusalError{"wrong-audience"}
	}
	return principalOf(c), nil
}

// ask is identity's introspection answer about token (RFC 7662), the Reader authenticating as its
// own Client.
func (r *Reader) ask(ctx context.Context, token string) (claims, error) {
	var c claims
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.IntrospectURL, strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return c, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(r.cfg.ClientID), url.QueryEscape(r.cfg.ClientSecret))
	res, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return c, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return c, fmt.Errorf("identity: introspection answered %d", res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(&c)
	return c, err
}
