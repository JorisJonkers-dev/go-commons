package signin_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/JorisJonkers-dev/go-commons/identity/signin"
)

const (
	clientID = "notes"
	adaID    = "00000000-0000-4000-8000-0000000000a1"
	adaSID   = "00000000-0000-4000-8000-0000000000c1"
)

// start is now: x/oauth2 dates a token's expiry from the real clock.
var start = time.Now().UTC().Truncate(time.Second)

// issuer is identity as the kit sees it: discovery, its published key, and a token endpoint that
// answers every code with an access token for Ada, or with status when it is set.
type issuer struct {
	url    string
	key    *rsa.PrivateKey
	clock  *clock
	status int
	// claims edits the access token's claims before they are signed.
	claims func(map[string]any)
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &issuer{key: key, clock: &clock{now: start}}
	srv := httptest.NewServer(http.HandlerFunc(i.serve))
	t.Cleanup(srv.Close)
	i.url = srv.URL
	return i
}

func (i *issuer) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": i.url, "authorization_endpoint": i.url + "/oidc/authorize", "token_endpoint": i.url + "/oidc/token",
			"jwks_uri": i.url + "/oidc/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/oidc/keys":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &i.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	case "/oidc/token":
		if i.status != 0 {
			w.WriteHeader(i.status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": i.accessToken(), "token_type": "Bearer", "expires_in": 900})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// sign signs claims with the issuer's key, as typ.
func (i *issuer) sign(typ string, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: i.key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		panic(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return token
}

func (i *issuer) accessToken() string {
	now := i.clock.now
	c := map[string]any{
		"iss": i.url, "sub": adaID, "aud": []string{clientID}, "client_id": clientID, "iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(), "ver": "1.1", "kind": "user", "email": "ada@example.org",
		"name": "Ada Lovelace", "roles": []string{"user"}, "via": "session", "sid": adaSID, "two_factor": false,
	}
	if i.claims != nil {
		i.claims(c)
	}
	return i.sign("JWT", c)
}

// logoutToken is a back-channel logout token for sid, edited by edit.
func (i *issuer) logoutToken(edit func(map[string]any)) string {
	c := map[string]any{
		"iss": i.url, "sub": adaID, "aud": []string{clientID}, "iat": i.clock.now.Unix(), "exp": i.clock.now.Add(2 * time.Minute).Unix(),
		"jti": "j1", "sid": adaSID, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	if edit != nil {
		edit(c)
	}
	return i.sign("logout+jwt", c)
}

// app is the kit for the app at https://notes.test, with a browser's cookies kept by hand.
type app struct {
	t       *testing.T
	kit     *signin.Kit
	issuer  *issuer
	cookies map[string]*http.Cookie
}

func newApp(t *testing.T, i *issuer) *app {
	t.Helper()
	kit, err := signin.New(t.Context(), signin.Config{Issuer: i.url, ClientID: clientID, BaseURL: "https://notes.test", Now: i.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &app{t: t, kit: kit, issuer: i, cookies: map[string]*http.Cookie{}}
}

// do sends a request to h, carrying the browser's cookies and keeping the ones it sets.
func (a *app) do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	for _, c := range a.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		a.cookies[c.Name] = c
	}
	return rec
}

func (a *app) get(h http.Handler, target string) *httptest.ResponseRecorder {
	return a.do(h, httptest.NewRequestWithContext(a.t.Context(), http.MethodGet, target, nil))
}

// login starts a sign-in coming back to rd, and answers the authorization request it sent.
func (a *app) login(t *testing.T, rd string) url.Values {
	t.Helper()
	rec := a.get(a.kit.Handler(), "/login?rd="+url.QueryEscape(rd))
	return authorization(t, rec)
}

func authorization(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// signedIn is a browser signed in to the app as Ada, coming back to rd.
func (a *app) signedIn(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	q := a.login(t, "/notes")
	return a.get(a.kit.Handler(), "/callback?code=c1&state="+q.Get("state"))
}

// principal is who the browser is signed in as.
func (a *app) principal() (string, bool) {
	req := httptest.NewRequestWithContext(a.t.Context(), http.MethodGet, "/", nil)
	for _, c := range a.cookies {
		req.AddCookie(c)
	}
	p, ok := a.kit.Principal(req)
	return p.Subject, ok
}

func TestSigningInSendsTheBrowserToIdentityWithPKCE(t *testing.T) {
	a := newApp(t, newIssuer(t))

	q := a.login(t, "/notes")

	if q.Get("client_id") != clientID || q.Get("redirect_uri") != "https://notes.test/callback" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Fatalf("authorization request = %v", q)
	}
}

func TestTheCallbackSignsTheBrowserInAsTheAccessTokensPrincipalAndReturnsToWhereItStarted(t *testing.T) {
	a := newApp(t, newIssuer(t))

	rec := a.signedIn(t)

	if subject, ok := a.principal(); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/notes" || !ok || subject != adaID {
		t.Fatalf("callback = %d to %q, signed in as %q %v", rec.Code, rec.Header().Get("Location"), subject, ok)
	}
}

func TestASignInComesBackOnlyToAPathOnTheApp(t *testing.T) {
	for _, rd := range []string{"https://evil.test/", "//evil.test/", "notes", ""} {
		t.Run(rd, func(t *testing.T) {
			a := newApp(t, newIssuer(t))
			q := a.login(t, rd)
			rec := a.get(a.kit.Handler(), "/callback?code=c1&state="+q.Get("state"))
			if rec.Header().Get("Location") != "/" {
				t.Fatalf("came back to %q", rec.Header().Get("Location"))
			}
		})
	}
}

func TestACallbackTheBrowserDidNotStartIsRefused(t *testing.T) {
	a := newApp(t, newIssuer(t))
	q := a.login(t, "/notes")
	delete(a.cookies, "signin_pending")

	if rec := a.get(a.kit.Handler(), "/callback?code=c1&state="+q.Get("state")); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestASignInUsedOnceCannotBeUsedAgain(t *testing.T) {
	a := newApp(t, newIssuer(t))
	q := a.login(t, "/notes")
	a.get(a.kit.Handler(), "/callback?code=c1&state="+q.Get("state"))

	if rec := a.get(a.kit.Handler(), "/callback?code=c1&state="+q.Get("state")); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestASignInOlderThanTenMinutesIsRefused(t *testing.T) {
	i := newIssuer(t)
	a := newApp(t, i)
	q := a.login(t, "/notes")
	i.clock.now = i.clock.now.Add(11 * time.Minute)

	if rec := a.get(a.kit.Handler(), "/callback?code=c1&state="+q.Get("state")); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestACodeIdentityRefusesSignsNoOneIn(t *testing.T) {
	i := newIssuer(t)
	i.status = http.StatusBadRequest
	a := newApp(t, i)

	if rec := a.signedIn(t); rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAnAccessTokenForAnotherClientSignsNoOneIn(t *testing.T) {
	i := newIssuer(t)
	i.claims = func(c map[string]any) { c["aud"] = []string{"grafana"} }
	a := newApp(t, i)

	if rec := a.signedIn(t); rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestASessionEndsWhenItsAccessTokenExpires(t *testing.T) {
	i := newIssuer(t)
	a := newApp(t, i)
	a.signedIn(t)
	i.clock.now = i.clock.now.Add(16 * time.Minute)

	if _, ok := a.principal(); ok {
		t.Fatal("still signed in")
	}
}

func TestABrowserWithoutASessionIsSignedInAsNoOne(t *testing.T) {
	if _, ok := newApp(t, newIssuer(t)).principal(); ok {
		t.Fatal("signed in")
	}
}

func (a *app) logout(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(a.t.Context(), http.MethodPost, "/back-channel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.kit.Handler().ServeHTTP(rec, req)
	return rec
}

func TestALogoutTokenEndsTheAppSessionsOfItsSingleSignOnSession(t *testing.T) {
	i := newIssuer(t)
	a := newApp(t, i)
	a.signedIn(t)

	rec := a.logout(i.logoutToken(nil))

	if _, ok := a.principal(); rec.Code != http.StatusOK || ok {
		t.Fatalf("logout = %d, still signed in %v", rec.Code, ok)
	}
}

func TestALogoutTokenForAnotherSessionEndsNothing(t *testing.T) {
	i := newIssuer(t)
	a := newApp(t, i)
	a.signedIn(t)

	a.logout(i.logoutToken(func(c map[string]any) { c["sid"] = "another" }))

	if _, ok := a.principal(); !ok {
		t.Fatal("signed out")
	}
}

func TestAnythingButALogoutTokenIsRefused(t *testing.T) {
	i := newIssuer(t)
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"not a JWT", "nonsense"},
		{"no sid", i.logoutToken(func(c map[string]any) { delete(c, "sid") })},
		{"a nonce", i.logoutToken(func(c map[string]any) { c["nonce"] = "n" })},
		{"no logout event", i.logoutToken(func(c map[string]any) { c["events"] = map[string]any{} })},
		{"another Client's", i.logoutToken(func(c map[string]any) { c["aud"] = []string{"grafana"} })},
		{"events that are not an object", i.logoutToken(func(c map[string]any) { c["events"] = "logout" })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := newApp(t, i).logout(tc.token); rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", rec.Code)
			}
		})
	}
}

// fresh is a handler behind RequireRecentTwoFactor(minutes) that answers 200.
func fresh(a *app, minutes int) http.Handler {
	return a.kit.RequireRecentTwoFactor(minutes)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
}

func TestARecentTwoFactorProofLetsTheRequestThrough(t *testing.T) {
	i := newIssuer(t)
	i.claims = func(c map[string]any) {
		c["two_factor"], c["two_factor_at"] = true, i.clock.now.Add(-4*time.Minute).Unix()
	}
	a := newApp(t, i)
	a.signedIn(t)

	if rec := a.get(fresh(a, 5), "/pay"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAStaleTwoFactorProofIsSentToIdentityToProveItAgain(t *testing.T) {
	i := newIssuer(t)
	i.claims = func(c map[string]any) {
		c["two_factor"], c["two_factor_at"] = true, i.clock.now.Add(-6*time.Minute).Unix()
	}
	a := newApp(t, i)
	a.signedIn(t)

	q := authorization(t, a.get(fresh(a, 5), "/pay?amount=3"))

	if q.Get("acr_values") != "mfa" || q.Get("max_age") != "300" {
		t.Fatalf("authorization request = %v", q)
	}
	i.claims = func(c map[string]any) { c["two_factor"], c["two_factor_at"] = true, i.clock.now.Unix() }
	if rec := a.get(a.kit.Handler(), "/callback?code=c2&state="+q.Get("state")); rec.Header().Get("Location") != "/pay?amount=3" {
		t.Fatalf("came back to %q", rec.Header().Get("Location"))
	}
}

func TestAStepUpIdentityAnswersWithoutAFreshProofIsRefusedNotAskedAgain(t *testing.T) {
	a := newApp(t, newIssuer(t))
	a.signedIn(t)
	q := authorization(t, a.get(fresh(a, 5), "/pay"))

	if rec := a.get(a.kit.Handler(), "/callback?code=c2&state="+q.Get("state")); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestASessionThatNeverProvedTwoFactorIsSentToProveIt(t *testing.T) {
	a := newApp(t, newIssuer(t))
	a.signedIn(t)

	if q := authorization(t, a.get(fresh(a, 5), "/pay")); q.Get("acr_values") != "mfa" {
		t.Fatalf("authorization request = %v", q)
	}
}

func TestAStepUpAsksForBetweenOneAndSixtyMinutes(t *testing.T) {
	for _, tc := range []struct {
		minutes int
		maxAge  string
	}{{0, "60"}, {90, "3600"}} {
		t.Run(tc.maxAge, func(t *testing.T) {
			a := newApp(t, newIssuer(t))
			a.signedIn(t)
			if q := authorization(t, a.get(fresh(a, tc.minutes), "/pay")); q.Get("max_age") != tc.maxAge {
				t.Fatalf("max_age = %q", q.Get("max_age"))
			}
		})
	}
}

func TestAStepUpWithoutASessionSignsInFirst(t *testing.T) {
	a := newApp(t, newIssuer(t))

	if q := authorization(t, a.get(fresh(a, 5), "/pay")); q.Get("acr_values") != "" || q.Get("client_id") != clientID {
		t.Fatalf("authorization request = %v", q)
	}
}

func TestAKitForAnIssuerThatCannotBeDiscoveredIsAnError(t *testing.T) {
	if _, err := signin.New(t.Context(), signin.Config{Issuer: "http://127.0.0.1:1", ClientID: clientID}); err == nil {
		t.Fatal("no error")
	}
}

func TestAKitWithoutAClientIsAnError(t *testing.T) {
	if _, err := signin.New(t.Context(), signin.Config{Issuer: newIssuer(t).url}); err == nil {
		t.Fatal("no error")
	}
}
