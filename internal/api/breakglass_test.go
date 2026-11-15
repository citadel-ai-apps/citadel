package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// withAPIOperators adds person:oncall and person:second with the operator flag.
func withAPIOperators(t *testing.T, f authzFixture) {

	t.Helper()
	ctx := context.Background()
	if err := f.srv.db.Tx(ctx, func(tx bun.Tx) error {

		for _, id := range []string{"oncall", "second"} {

			if _, err := f.srv.ident.Create(ctx, tx, identity.Platform(), identity.CreateOptions{ID: id}); err != nil {

				return err
			}
		}
		return nil
	}); err != nil {

		t.Fatal(err)
	}
	h := f.srv.SocketHandler()
	for _, id := range []string{"person:oncall", "person:second"} {

		if w := socketPost(h, "/api/v1/admin/principals/"+id+"/operator", "platform", `{"operator":true}`); w.Code != http.StatusOK {

			t.Fatalf("set operator %s = %d: %s", id, w.Code, w.Body)
		}
	}
}

// Only a named operator opens break-glass, even over the root socket: the
// session now opens the tenant in the portal for whoever it names.
func TestBreakglassOpenNeedsANamedOperator(t *testing.T) {

	f := newAuthzFixture(t)
	withAPIOperators(t, f)
	h := f.srv.SocketHandler()
	body := `{"reason":"incident 42"}`

	for _, who := range []string{"platform", "person:owner", "person:stranger"} {

		if w := socketPost(h, "/api/v1/admin/tenants/demo/breakglass", who, body); w.Code != http.StatusForbidden {

			t.Errorf("open as %s = %d, want 403: %s", who, w.Code, w.Body)
		}
	}
	if w := socketPost(h, "/api/v1/admin/principals/platform/operator", "platform", `{"operator":true}`); w.Code != http.StatusBadRequest {

		t.Errorf("flagging the platform principal = %d, want 400: %s", w.Code, w.Body)
	}
	w := socketPost(h, "/api/v1/admin/tenants/demo/breakglass", "person:oncall", body)
	if w.Code != http.StatusCreated {

		t.Fatalf("open as oncall = %d: %s", w.Code, w.Body)
	}
	var out struct {
		Grant  store.Grant `json:"grant"`
		Portal string      `json:"portal_path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Portal != "/t/demo" {

		t.Errorf("open response = %s (%v)", w.Body, err)
	}
}

// Review is another operator's, once. Close is the requester's or another
// operator's, never the tenant's, and only while the session is open.
func TestBreakglassReviewAndClose(t *testing.T) {

	f := newAuthzFixture(t)
	withAPIOperators(t, f)
	h := f.srv.SocketHandler()

	w := socketPost(h, "/api/v1/admin/tenants/demo/breakglass", "person:oncall", `{"reason":"incident 42"}`)
	if w.Code != http.StatusCreated {

		t.Fatalf("open = %d: %s", w.Code, w.Body)
	}
	var out struct {
		Grant store.Grant `json:"grant"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {

		t.Fatal(err)
	}
	gid := out.Grant.ID
	review := `{"outcome":"justified","notes":"as stated"}`

	for who, want := range map[string]int{
		"person:oncall": http.StatusForbidden, // the opener
		"person:owner":  http.StatusForbidden, // not an operator
		"platform":      http.StatusForbidden, // names nobody
	} {

		if w := socketPost(h, "/api/v1/admin/grants/"+gid+"/review", who, review); w.Code != want {

			t.Errorf("review as %s = %d, want %d: %s", who, w.Code, want, w.Body)
		}
	}

	// The tenant's own revoke refuses a break-glass row, on the TCP API too.
	if code := doBody(f.srv.APIHandler(), http.MethodDelete, "/api/v1/tenants/demo/grants/"+gid, f.owner, ""); code != http.StatusForbidden {

		t.Errorf("tenant revoke = %d, want 403", code)
	}
	if w := socketPost(h, "/api/v1/admin/grants/"+gid+"/close", "person:owner", `{}`); w.Code != http.StatusForbidden {

		t.Errorf("close as owner = %d, want 403: %s", w.Code, w.Body)
	}
	if w := socketPost(h, "/api/v1/admin/grants/"+gid+"/close", "person:second", `{"reason":"done elsewhere"}`); w.Code != http.StatusOK {

		t.Fatalf("close as second = %d: %s", w.Code, w.Body)
	}
	if w := socketPost(h, "/api/v1/admin/grants/"+gid+"/close", "person:oncall", `{}`); w.Code != http.StatusConflict {

		t.Errorf("second close = %d, want 409: %s", w.Code, w.Body)
	}

	if w := socketPost(h, "/api/v1/admin/grants/"+gid+"/review", "person:second", review); w.Code != http.StatusOK {

		t.Fatalf("review as second = %d: %s", w.Code, w.Body)
	}
	if w := socketPost(h, "/api/v1/admin/grants/"+gid+"/review", "person:second", review); w.Code != http.StatusConflict {

		t.Errorf("second review = %d, want 409: %s", w.Code, w.Body)
	}
}

// The block is the §14.3 rule exactly: an unreviewed session blocks its opener
// only once it is more than 24h old. Inside that window further sessions open;
// past it they are refused until another operator reviews, and the review
// lifts the block.
func TestUnreviewedBlockStartsAfterTheReviewWindow(t *testing.T) {

	f := newAuthzFixture(t)
	withAPIOperators(t, f)
	h := f.srv.SocketHandler()
	open := func() (int, string) {

		w := socketPost(h, "/api/v1/admin/tenants/demo/breakglass", "person:oncall", `{"reason":"incident 42"}`)
		var out struct {
			Grant store.Grant `json:"grant"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out.Grant.ID
	}

	code, first := open()
	if code != http.StatusCreated {

		t.Fatalf("first open = %d", code)
	}
	if code, _ := open(); code != http.StatusCreated {

		t.Fatalf("second open inside 24h, first unreviewed = %d, want 201: a young session blocks nothing", code)
	}

	ctx := context.Background()
	old := time.Now().UTC().Add(-store.ReviewWindow - time.Hour)
	if err := f.srv.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := tx.NewUpdate().Model((*store.Grant)(nil)).
			Set("requested_at = ?", old).Set("expires_at = ?", old.Add(store.BreakglassTTL)).
			Where("id = ?", first).Exec(ctx)
		return err
	}); err != nil {

		t.Fatal(err)
	}
	if code, _ := open(); code != http.StatusConflict {

		t.Fatalf("open with a session unreviewed past 24h = %d, want 409", code)
	}
	if w := socketPost(h, "/api/v1/admin/grants/"+first+"/review", "person:second",
		`{"outcome":"justified","notes":"as stated"}`); w.Code != http.StatusOK {

		t.Fatalf("review = %d: %s", w.Code, w.Body)
	}
	if code, _ := open(); code != http.StatusCreated {

		t.Fatalf("open after the review = %d, want 201", code)
	}
}

// The list shows every unreviewed session, not only the overdue ones: a session
// opened a minute ago still needs its verdict.
func TestBreakglassListShowsYoungUnreviewedSessions(t *testing.T) {

	f := newAuthzFixture(t)
	withAPIOperators(t, f)
	h := f.srv.SocketHandler()
	if w := socketPost(h, "/api/v1/admin/tenants/demo/breakglass", "person:oncall", `{"reason":"incident 42"}`); w.Code != http.StatusCreated {

		t.Fatalf("open = %d: %s", w.Code, w.Body)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/breakglass", nil)
	req.Header.Set(PrincipalHeader, "platform")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out struct {
		Open, Unreviewed, Overdue []store.Grant
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {

		t.Fatalf("list = %d %s: %v", w.Code, w.Body, err)
	}
	if len(out.Open) != 1 || len(out.Unreviewed) != 1 || len(out.Overdue) != 0 {

		t.Errorf("list = %s, want one open, one unreviewed, none overdue", w.Body)
	}
}
