package identity

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"
)

type principalKey struct{}

// WithPrincipal is ctx carrying p, as Middleware leaves it for the handlers it wraps.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext is the Principal Middleware read for the request, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// Middleware reads each request's Principal and passes it on in the request's context. A request
// whose Principal is refused is answered 401, and one whose Issuer keys cannot be read 503.
func (r *Reader) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, err := r.Read(req)
		var refused *RefusalError
		switch {
		case errors.As(err, &refused):
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		case err != nil:
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		default:
			next.ServeHTTP(w, req.WithContext(WithPrincipal(req.Context(), p)))
		}
	})
}

// guard lets a request through when allow says so of its Principal, answers 403 when it does not,
// and 401 when the request carries none.
func guard(allow func(Principal) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			p, ok := FromContext(req.Context())
			switch {
			case !ok:
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			case !allow(p):
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			default:
				next.ServeHTTP(w, req)
			}
		})
	}
}

// RequireRole lets through a caller holding role on the app's Client. It takes the string-typed
// App Roles deploy-kit generates as readily as a plain string.
func RequireRole[R ~string](role R) func(http.Handler) http.Handler {
	return guard(func(p Principal) bool { return slices.Contains(p.Roles, string(role)) })
}

// RefuseTools turns away a tool acting for a User, so a tool can read but never, say, delete.
func RefuseTools() func(http.Handler) http.Handler {
	return guard(func(p Principal) bool { return p.Via != ViaTool })
}

// RequireUser lets through only a person, never a Machine Identity.
func RequireUser() func(http.Handler) http.Handler {
	return guard(func(p Principal) bool { return p.Kind == KindUser })
}

// RequireMachine lets through only a Machine Identity, never a person.
func RequireMachine() func(http.Handler) http.Handler {
	return guard(func(p Principal) bool { return p.Kind == KindMachine })
}

// RequireRecentTwoFactor lets through a session that proved two-factor within minutes. A session
// whose proof is older, or that has none, is sent to the Gate's step-up on the app's own host and
// comes back to the same page; a Personal Token, a tool or a machine, which no browser carries
// through a step-up, is answered 403.
func RequireRecentTwoFactor(minutes int) func(http.Handler) http.Handler {
	window := time.Duration(minutes) * time.Minute
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			p, ok := FromContext(req.Context())
			switch {
			case !ok:
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			case p.TwoFactorAt != nil && time.Since(*p.TwoFactorAt) <= window:
				next.ServeHTTP(w, req)
			case p.Via == ViaSession:
				target := "/.auth/step-up?" + url.Values{"minutes": {strconv.Itoa(minutes)}, "rd": {req.URL.RequestURI()}}.Encode()
				http.Redirect(w, req, target, http.StatusSeeOther)
			default:
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			}
		})
	}
}
