// Package secure sets the browser hardening headers every response of an estate service carries.
//
// Three are the same everywhere: no MIME sniffing, no framing, and a referrer that leaves the
// origin only as the origin. The content security policy is each service's own, since each loads
// different things; the permissions policy and Strict-Transport-Security are each service's to
// set, with a default that grants nothing and no HSTS.
package secure

import (
	"errors"
	"net/http"
)

// DefaultPermissions grants a page none of the powerful features.
const DefaultPermissions = "camera=(), microphone=(), geolocation=()"

// Policy is what one service says about the headers that differ between services.
type Policy struct {
	// ContentSecurityPolicy is the service's content security policy. Required: a service that
	// says nothing would be one that allows everything.
	ContentSecurityPolicy string
	// Permissions is the Permissions-Policy header; empty means DefaultPermissions.
	Permissions string
	// HSTS is the Strict-Transport-Security header; empty sends none, which is right where TLS
	// ends before the service and the proxy sets it, or on a local run over plain HTTP.
	HSTS string
}

// ErrNoContentSecurityPolicy is returned for a policy without a content security policy.
var ErrNoContentSecurityPolicy = errors.New("secure: a policy names its content security policy")

// Headers returns the middleware that sets every header of p on each response, before the
// handler it wraps writes anything.
func Headers(p Policy) (func(http.Handler) http.Handler, error) {
	if p.ContentSecurityPolicy == "" {
		return nil, ErrNoContentSecurityPolicy
	}
	permissions := p.Permissions
	if permissions == "" {
		permissions = DefaultPermissions
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", p.ContentSecurityPolicy)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Permissions-Policy", permissions)
			if p.HSTS != "" {
				h.Set("Strict-Transport-Security", p.HSTS)
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}
