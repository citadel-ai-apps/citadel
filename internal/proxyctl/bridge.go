package proxyctl

import (
	"crypto/sha256"
	"encoding/base64"
)

// AdminBridgePath is where the edge serves the PocketBase admin handoff page
// on every tenant hostname. The path is reserved: requests to it never reach
// the tenant, so a tenant cannot serve its own page here and collect tokens.
const AdminBridgePath = "/_citadel/admin"

// bridgeScript moves the portal's handoff into the admin UI's session store.
//
// The payload is in the URL fragment, which the browser never sends, so the
// token reaches neither this edge nor the tenant's server. Only the two
// storage keys the admin UI reads are writable, so the page cannot be used to
// plant arbitrary localStorage on a tenant's origin. The fragment is cleared
// from history before leaving.
const bridgeScript = `(function(){` +
	`var ok={"__pb_superusers__/_":1,"pb_admin_auth":1};` +
	`try{` +
	`var p=JSON.parse(atob(location.hash.slice(1).replace(/-/g,"+").replace(/_/g,"/")));` +
	`var v=JSON.parse(p.v);` +
	`if(ok[p.k]===1&&v&&typeof v.token==="string"){localStorage.setItem(p.k,p.v);}` +
	`}catch(e){}` +
	`history.replaceState(null,"",location.pathname);` +
	`location.replace("/_/");` +
	`})();`

const bridgeHTML = `<!doctype html><meta charset="utf-8"><title>Opening PocketBase admin…</title>` +
	`<p>Opening PocketBase admin…</p><script>` + bridgeScript + `</script>`

// bridgeCSP allows exactly the inline script above and nothing else.
var bridgeCSP = func() string {

	sum := sha256.Sum256([]byte(bridgeScript))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

// bridgeRoute is the subroute entry that serves the handoff page.
func bridgeRoute() map[string]any {

	return map[string]any{
		"match": []any{map[string]any{"path": []string{AdminBridgePath}}},
		"handle": []any{map[string]any{
			"handler":     "static_response",
			"status_code": 200,
			"headers": map[string]any{
				"Content-Type":            []string{"text/html; charset=utf-8"},
				"Cache-Control":           []string{"no-store"},
				"Referrer-Policy":         []string{"no-referrer"},
				"Content-Security-Policy": []string{bridgeCSP},
				"X-Content-Type-Options":  []string{"nosniff"},
			},
			"body": bridgeHTML,
		}},
		"terminal": true,
	}
}
