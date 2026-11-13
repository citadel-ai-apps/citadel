package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func socketPost(h http.Handler, path, principal, body string) *httptest.ResponseRecorder {

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PrincipalHeader, principal)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func insertPending(t *testing.T, f authzFixture, id, kind string, tier int) {

	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := f.srv.db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertGrant(ctx, tx, store.Grant{
			ID: id, TenantID: "demo", Kind: kind, Direction: grantpolicy.Direction(kind),
			Subject: "x", Tier: tier, Decision: store.DecisionPending,
			RequestedBy: "person:owner", RequestedAt: now, PolicyVersion: grantpolicy.PolicyVersion,
			ExpiresAt: now.Add(time.Hour),
		})
	}); err != nil {

		t.Fatal(err)
	}
}

// Break-glass has one door (§14.3). Neither the platform nor an operator may
// request a Tier-3 kind as an ordinary grant, and a Tier-3 row is never
// approved through the generic path, where it would escape the 60-minute box,
// the notifications and the review.
func TestBreakglassNeverGoesThroughTheGenericGrantPath(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.SocketHandler()
	for _, who := range []string{"platform", "person:owner"} {

		w := socketPost(h, "/api/v1/tenants/demo/grants", who,
			`{"kind":"`+store.GrantOperatorDataAccess+`","subject":"pb_data","justification":"x"}`)
		if w.Code != http.StatusForbidden {

			t.Errorf("Tier-3 request as %s = %d, want 403: %s", who, w.Code, w.Body)
		}
	}
	insertPending(t, f, "g-bg", store.GrantOperatorDataAccess, grantpolicy.TierBreakGlass)
	w := socketPost(h, "/api/v1/admin/grants/g-bg/approve", "person:stranger",
		`{"justification":"x","expires_in_days":30}`)
	if w.Code != http.StatusForbidden {

		t.Errorf("approving a Tier-3 row = %d, want 403: %s", w.Code, w.Body)
	}
}

// Tier 2 is a named human approver, and the §14.2 expiry is a ceiling.
func TestGrantDecisionNeedsAPersonAndRespectsTheExpiryCeiling(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.SocketHandler()
	insertPending(t, f, "g-t2", store.GrantLogAccess, grantpolicy.TierHuman)

	if w := socketPost(h, "/api/v1/admin/grants/g-t2/approve", "platform", `{"justification":"x"}`); w.Code != http.StatusForbidden {

		t.Errorf("approval by the platform principal = %d, want 403: %s", w.Code, w.Body)
	}
	// log_access expires after 7 days at most.
	if w := socketPost(h, "/api/v1/admin/grants/g-t2/approve", "person:stranger",
		`{"justification":"x","expires_in_days":30}`); w.Code != http.StatusUnprocessableEntity {

		t.Errorf("approval past the expiry ceiling = %d, want 422: %s", w.Code, w.Body)
	}
	if w := socketPost(h, "/api/v1/admin/grants/g-t2/approve", "person:stranger",
		`{"justification":"x","expires_in_days":3}`); w.Code != http.StatusOK {

		t.Errorf("approval within the ceiling = %d, want 200: %s", w.Code, w.Body)
	}
}

// A frozen tenant's access does not change (§14.5): no grant request and no
// decision until an operator lifts the freeze, which needs a reason.
func TestAFrozenTenantsGrantsDoNotMove(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.SocketHandler()
	ctx := context.Background()
	insertPending(t, f, "g-t2", store.GrantLogAccess, grantpolicy.TierHuman)
	if err := f.srv.db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetFrozen(ctx, tx, "demo", "attestation/at-1: enforcement without grant")
	}); err != nil {

		t.Fatal(err)
	}
	if w := socketPost(h, "/api/v1/tenants/demo/grants", "person:owner",
		`{"kind":"log_access","subject":"x","justification":"x"}`); w.Code != http.StatusConflict {

		t.Errorf("grant request on a frozen tenant = %d, want 409: %s", w.Code, w.Body)
	}
	if w := socketPost(h, "/api/v1/admin/grants/g-t2/approve", "person:stranger", `{"justification":"x"}`); w.Code != http.StatusConflict {

		t.Errorf("grant decision on a frozen tenant = %d, want 409: %s", w.Code, w.Body)
	}

	del := func(body string) int {

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/tenants/demo/freeze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(PrincipalHeader, "person:stranger")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if got := del(""); got != http.StatusBadRequest {

		t.Errorf("unfreeze with no reason = %d, want 400", got)
	}
	if got := del(`{"reason":"rule traced to a test harness; removed"}`); got != http.StatusOK {

		t.Errorf("unfreeze with a reason = %d, want 200", got)
	}
	if w := socketPost(h, "/api/v1/admin/grants/g-t2/approve", "person:stranger", `{"justification":"x"}`); w.Code != http.StatusOK {

		t.Errorf("grant decision after unfreeze = %d, want 200: %s", w.Code, w.Body)
	}
}
