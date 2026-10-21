// Package signin is the Go sign-in kit for a native app on identity: the code flow with PKCE through
// go-oidc and golang.org/x/oauth2, a session per browser holding the Principal the access token
// states, back-channel logout, and step-up to a fresh two-factor proof. It reimplements no part of
// the flow; it is held to the Principal contract's flow-conformance suite
// (github.com/JorisJonkers-dev/identity/contract/flows).
package signin

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/JorisJonkers-dev/go-commons/identity"
)

const (
	// The kit's own routes, under the app's base URL.
	LoginPath         = "/login"
	CallbackPath      = "/callback"
	BackChannelPath   = "/back-channel-logout"
	sessionCookie     = "signin_session"
	pendingCookie     = "signin_pending"
	pendingLifetime   = 10 * time.Minute
	logoutEvent       = "http://schemas.openid.net/event/backchannel-logout"
	maxStepUpMinutes  = 60
	defaultReturnPath = "/"
)

// Config is the app's Client at identity.
type Config struct {
	// Issuer is identity's URL.
	Issuer string
	// ClientID is the app's Client.
	ClientID string
	// ClientSecret is the app's secret; empty for a public Client, which proves each code with PKCE.
	ClientSecret string
	// BaseURL is where browsers reach the app; the redirect URI is BaseURL + CallbackPath.
	BaseURL string
	// HTTPClient reaches identity; http.DefaultClient when nil.
	HTTPClient *http.Client
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Kit signs people in to one app.
type Kit struct {
	cfg Config
	// secure is whether browsers reach the app over HTTPS, so its cookies are Secure, also behind
	// an edge that terminates TLS.
	secure   bool
	oauth    oauth2.Config
	logouts  *oidc.IDTokenVerifier
	reader   *identity.Reader
	mu       sync.Mutex
	sessions map[string]session
	pending  map[string]pending
}

// session is a browser signed in to the app: the Principal its access token states, until the
// token expires or identity ends the Single sign-on session behind it.
type session struct {
	principal identity.Principal
	expires   time.Time
}

// pending is a sign-in under way: its PKCE verifier, where to come back to, and how fresh a
// two-factor proof it asked for; 0 when it asked none.
type pending struct {
	verifier string
	rd       string
	started  time.Time
	fresh    time.Duration
}

// New discovers identity at cfg.Issuer and returns a Kit for the app.
func New(ctx context.Context, cfg Config) (*Kit, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, cfg.HTTPClient), cfg.Issuer)
	if err != nil {
		return nil, err
	}
	reader, err := identity.New(identity.Config{Issuer: cfg.Issuer, ClientID: cfg.ClientID, HTTPClient: cfg.HTTPClient, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	return &Kit{
		cfg: cfg, secure: strings.HasPrefix(cfg.BaseURL, "https://"),
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: provider.Endpoint(),
			RedirectURL: strings.TrimSuffix(cfg.BaseURL, "/") + CallbackPath, Scopes: []string{oidc.ScopeOpenID},
		},
		// A logout token is a JWT the Issuer signs for this Client, with no nonce (OpenID Connect
		// Back-Channel Logout 1.0, 2.6).
		logouts:  provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, Now: cfg.Now}),
		reader:   reader,
		sessions: map[string]session{},
		pending:  map[string]pending{},
	}, nil
}

// Handler serves the kit's routes: LoginPath, CallbackPath and BackChannelPath.
func (k *Kit) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+LoginPath, k.login)
	mux.HandleFunc("GET "+CallbackPath, k.callback)
	mux.HandleFunc("POST "+BackChannelPath, k.backChannelLogout)
	return mux
}

// Principal is who is signed in to the app in r's browser.
func (k *Kit) Principal(r *http.Request) (identity.Principal, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return identity.Principal{}, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.sessions[c.Value]
	if !ok || !k.cfg.Now().Before(s.expires) {
		delete(k.sessions, c.Value)
		return identity.Principal{}, false
	}
	return s.principal, true
}

// login starts a sign-in, coming back to rd, a path on the app.
func (k *Kit) login(w http.ResponseWriter, r *http.Request) {
	k.start(w, r, returnPath(r.URL.Query().Get("rd")), 0)
}

// start sends the browser to identity, asking for a two-factor proof within fresh when it is not 0.
func (k *Kit) start(w http.ResponseWriter, r *http.Request, rd string, fresh time.Duration) {
	state, verifier := rand.Text(), oauth2.GenerateVerifier()
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if fresh > 0 {
		opts = append(opts,
			oauth2.SetAuthURLParam("acr_values", "mfa"),
			oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(fresh/time.Second))))
	}
	k.mu.Lock()
	k.pending[state] = pending{verifier: verifier, rd: rd, started: k.cfg.Now(), fresh: fresh}
	k.mu.Unlock()
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure whenever the app is served over HTTPS
		Name: pendingCookie, Value: state, Path: CallbackPath, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: k.secure, MaxAge: int(pendingLifetime / time.Second),
	})
	http.Redirect(w, r, k.oauth.AuthCodeURL(state, opts...), http.StatusSeeOther)
}

// callback redeems identity's code and starts the app's session.
func (k *Kit) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	c, err := r.Cookie(pendingCookie)
	if err != nil || c.Value != state {
		http.Error(w, "This sign-in did not start in this browser. Sign in again.", http.StatusBadRequest)
		return
	}
	k.mu.Lock()
	p, ok := k.pending[state]
	delete(k.pending, state)
	k.mu.Unlock()
	if !ok || k.cfg.Now().Sub(p.started) > pendingLifetime {
		http.Error(w, "This sign-in has expired. Sign in again.", http.StatusBadRequest)
		return
	}
	ctx := oidc.ClientContext(r.Context(), k.cfg.HTTPClient)
	token, err := k.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(p.verifier))
	if err != nil {
		http.Error(w, "identity did not accept this sign-in. Sign in again.", http.StatusBadGateway)
		return
	}
	principal, err := k.read(r.Context(), token.AccessToken)
	if err != nil {
		http.Error(w, "identity's access token could not be read. Sign in again.", http.StatusBadGateway)
		return
	}
	// A step-up identity did not answer with a fresh proof would only ask again, without end.
	if p.fresh > 0 && !k.proved(principal, p.fresh) {
		http.Error(w, "This needs a recent two-factor proof, and identity sent none.", http.StatusForbidden)
		return
	}
	id := rand.Text()
	k.mu.Lock()
	k.sessions[id] = session{principal: principal, expires: token.Expiry}
	k.mu.Unlock()
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure whenever the app is served over HTTPS
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: k.secure,
	})
	http.Redirect(w, r, p.rd, http.StatusSeeOther)
}

// read is the Principal an access token states, read through the identity package as a bearer
// token is.
func (k *Kit) read(ctx context.Context, accessToken string) (identity.Principal, error) {
	// A fixed method and path never fail to make a request.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return k.reader.Read(req)
}

// backChannelLogout ends every app session of the Single sign-on session a logout token names.
func (k *Kit) backChannelLogout(w http.ResponseWriter, r *http.Request) {
	raw := r.PostFormValue("logout_token")
	token, err := k.logouts.Verify(oidc.ClientContext(r.Context(), k.cfg.HTTPClient), raw)
	var claims struct {
		SID    string         `json:"sid"`
		Events map[string]any `json:"events"`
		Nonce  *string        `json:"nonce"`
	}
	if err == nil {
		err = token.Claims(&claims)
	}
	if err != nil || claims.SID == "" || claims.Nonce != nil || claims.Events[logoutEvent] == nil {
		http.Error(w, "not a logout token", http.StatusBadRequest)
		return
	}
	k.mu.Lock()
	for id, s := range k.sessions {
		if s.principal.SID == claims.SID {
			delete(k.sessions, id)
		}
	}
	k.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// RequireRecentTwoFactor lets a request through when its session proved two-factor within minutes,
// from 1 to 60. A session that did not is sent to identity to prove it, and comes back here. A
// request with no session is sent to sign in.
func (k *Kit) RequireRecentTwoFactor(minutes int) func(http.Handler) http.Handler {
	window := time.Duration(min(max(minutes, 1), maxStepUpMinutes)) * time.Minute
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := k.Principal(r)
			if !ok {
				k.start(w, r, r.URL.RequestURI(), 0)
				return
			}
			if k.proved(p, window) {
				next.ServeHTTP(w, r)
				return
			}
			k.start(w, r, r.URL.RequestURI(), window)
		})
	}
}

// proved reports whether p's session proved two-factor within window.
func (k *Kit) proved(p identity.Principal, window time.Duration) bool {
	return p.TwoFactorAt != nil && k.cfg.Now().Sub(*p.TwoFactorAt) <= window
}

// returnPath is rd when it is a path on the app, and "/" otherwise, so a sign-in never ends on
// another site.
func returnPath(rd string) string {
	u, err := url.Parse(rd)
	if err != nil || rd == "" || !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || u.Host != "" {
		return defaultReturnPath
	}
	return rd
}
