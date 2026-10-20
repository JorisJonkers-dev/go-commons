package identity_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JorisJonkers-dev/go-commons/identity"
)

// Role is an App Role as deploy-kit generates it: a string type of the app's own.
type Role string

const editor Role = "editor"

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

// serve is guard over ok, answering a request to target from p, or from no Principal when p is nil.
func serve(t *testing.T, guard func(http.Handler) http.Handler, p *identity.Principal, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)
	if p != nil {
		req = req.WithContext(identity.WithPrincipal(req.Context(), *p))
	}
	rec := httptest.NewRecorder()
	guard(ok).ServeHTTP(rec, req)
	return rec
}

func ada(edit func(p *identity.Principal)) *identity.Principal {
	p := &identity.Principal{Subject: "ada", Kind: identity.KindUser, Roles: []string{"user"}, Via: identity.ViaSession, SID: "s", Ver: "1.0"}
	edit(p)
	return p
}

func unchanged(*identity.Principal) {}

func TestRequireRoleLetsThroughACallerHoldingTheGeneratedRole(t *testing.T) {
	p := ada(func(p *identity.Principal) { p.Roles = []string{"user", "editor"} })

	if rec := serve(t, identity.RequireRole(editor), p, "/pages"); rec.Code != http.StatusNoContent {
		t.Fatalf("RequireRole = %d", rec.Code)
	}
}

func TestRequireRoleAnswers403ToACallerWithoutTheRole(t *testing.T) {
	if rec := serve(t, identity.RequireRole("editor"), ada(unchanged), "/pages"); rec.Code != http.StatusForbidden {
		t.Fatalf("RequireRole = %d", rec.Code)
	}
}

func TestRefuseToolsAnswers403ToAToolActingForAUser(t *testing.T) {
	p := ada(func(p *identity.Principal) {
		p.Via, p.Actor = identity.ViaTool, &identity.Actor{ID: "mcp_1", Name: "Claude Code"}
	})

	if rec := serve(t, identity.RefuseTools(), p, "/pay"); rec.Code != http.StatusForbidden {
		t.Fatalf("RefuseTools = %d", rec.Code)
	}
}

func TestRefuseToolsLetsTheUserThemselvesThrough(t *testing.T) {
	if rec := serve(t, identity.RefuseTools(), ada(unchanged), "/pay"); rec.Code != http.StatusNoContent {
		t.Fatalf("RefuseTools = %d", rec.Code)
	}
}

func TestRequireUserAnswers403ToAMachine(t *testing.T) {
	p := ada(func(p *identity.Principal) { p.Kind, p.Via = identity.KindMachine, identity.ViaMachine })

	if rec := serve(t, identity.RequireUser(), p, "/"); rec.Code != http.StatusForbidden {
		t.Fatalf("RequireUser = %d", rec.Code)
	}
}

func TestRequireUserLetsAPersonThrough(t *testing.T) {
	if rec := serve(t, identity.RequireUser(), ada(unchanged), "/"); rec.Code != http.StatusNoContent {
		t.Fatalf("RequireUser = %d", rec.Code)
	}
}

func TestRequireMachineAnswers403ToAPerson(t *testing.T) {
	if rec := serve(t, identity.RequireMachine(), ada(unchanged), "/jobs"); rec.Code != http.StatusForbidden {
		t.Fatalf("RequireMachine = %d", rec.Code)
	}
}

func TestRequireMachineLetsAMachineThrough(t *testing.T) {
	p := ada(func(p *identity.Principal) { p.Kind, p.Via = identity.KindMachine, identity.ViaMachine })

	if rec := serve(t, identity.RequireMachine(), p, "/jobs"); rec.Code != http.StatusNoContent {
		t.Fatalf("RequireMachine = %d", rec.Code)
	}
}

func TestRequireRecentTwoFactorLetsAFreshEnoughProofThrough(t *testing.T) {
	at := time.Now().Add(-4 * time.Minute)
	p := ada(func(p *identity.Principal) { p.TwoFactor, p.TwoFactorAt = true, &at })

	if rec := serve(t, identity.RequireRecentTwoFactor(5), p, "/pay"); rec.Code != http.StatusNoContent {
		t.Fatalf("RequireRecentTwoFactor = %d", rec.Code)
	}
}

func TestRequireRecentTwoFactorSendsAStaleSessionToStepUpAndBack(t *testing.T) {
	at := time.Now().Add(-6 * time.Minute)
	p := ada(func(p *identity.Principal) { p.TwoFactor, p.TwoFactorAt = true, &at })

	rec := serve(t, identity.RequireRecentTwoFactor(5), p, "/pay?amount=3")

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/.auth/step-up?minutes=5&rd=%2Fpay%3Famount%3D3" {
		t.Fatalf("RequireRecentTwoFactor = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRequireRecentTwoFactorSendsASessionWithNoProofToStepUp(t *testing.T) {
	if rec := serve(t, identity.RequireRecentTwoFactor(5), ada(unchanged), "/pay"); rec.Code != http.StatusSeeOther {
		t.Fatalf("RequireRecentTwoFactor = %d", rec.Code)
	}
}

func TestRequireRecentTwoFactorAnswers403ToAPersonalTokenItCannotStepUp(t *testing.T) {
	p := ada(func(p *identity.Principal) { p.Via, p.SID = identity.ViaPersonalToken, "" })

	if rec := serve(t, identity.RequireRecentTwoFactor(5), p, "/pay"); rec.Code != http.StatusForbidden {
		t.Fatalf("RequireRecentTwoFactor = %d", rec.Code)
	}
}

func TestEveryHelperAnswers401ToARequestWithoutAPrincipal(t *testing.T) {
	for _, c := range []struct {
		name  string
		guard func(http.Handler) http.Handler
	}{
		{"RequireRole", identity.RequireRole("user")},
		{"RefuseTools", identity.RefuseTools()},
		{"RequireUser", identity.RequireUser()},
		{"RequireMachine", identity.RequireMachine()},
		{"RequireRecentTwoFactor", identity.RequireRecentTwoFactor(5)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if rec := serve(t, c.guard, nil, "/"); rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s = %d", c.name, rec.Code)
			}
		})
	}
}
