## Verdict

Exploitable. `GET /admin/users/export` is registered directly on the mux with `exportUsersHandler`, without the `requireAdmin` wrapper that the sibling `POST /admin/users/ban` and `POST /admin/users/unban` routes use. Any caller who can reach the mux - authenticated or not - can invoke `exportUsersHandler` and receive a CSV export of every user's ID, email, and role. Confidence: high.

## Source

The route registration in `RegisterRoutes` (admin.go:103, per the finding location - the current source line is the un-wrapped `mux.HandleFunc("GET /admin/users/export", exportUsersHandler)` call) is the point where the missing check is visible: `http.ServeMux` exposes no way to enumerate its registered handlers afterward, so registration time is the only place the omission shows. There is no attacker-controlled input beyond the bare HTTP request; the "source" here is the request reaching the mux at all, since nothing gates who may issue it.

## Fix

### File: admin.go

```go
package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
)

// User is a minimal user record for the admin export/ban endpoints.
type User struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type contextKey string

const userContextKey contextKey = "authUser"

// currentUser reads the authenticated user placed on the request context by
// the session middleware installed earlier in the chain.
func currentUser(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok
}

// requireAdmin wraps a handler so it only runs for callers whose session
// user has the admin role. Every sensitive admin route is expected to be
// registered through this wrapper.
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := currentUser(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// banUserHandler suspends a user account. It is only ever reached through
// requireAdmin, which is wired up at registration time in RegisterRoutes.
func banUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := setUserBanned(r.Context(), id, true); err != nil {
		http.Error(w, "failed to ban user", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setUserBanned marks the given user id as banned. Data access details are
// out of scope for this sample; only the flow into the sink matters here.
func setUserBanned(ctx context.Context, userID string, banned bool) error {
	return nil
}

// exportUsersHandler streams every user account, including email addresses,
// as a CSV attachment. This is at least as sensitive as banning a user - it
// discloses the full user table to whoever can reach the route.
func exportUsersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := loadAllUsers(r.Context())
	if err != nil {
		http.Error(w, "failed to load users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=users.csv")

	writer := csv.NewWriter(w)
	defer writer.Flush()
	_ = writer.Write([]string{"id", "email", "role"})
	for _, u := range users {
		_ = writer.Write([]string{fmtInt(u.ID), u.Email, u.Role})
	}
}

func loadAllUsers(ctx context.Context) ([]User, error) {
	return []User{}, nil
}

func fmtInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// RegisterRoutes wires the admin handlers onto the mux. Every sensitive
// admin handler - including exportUsersHandler, which discloses the full
// user table - is wrapped with requireAdmin so only admins can reach it.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/users/ban", requireAdmin(banUserHandler))
	mux.HandleFunc("POST /admin/users/unban", requireAdmin(unbanUserHandler))
	mux.HandleFunc("GET /admin/users/export", requireAdmin(exportUsersHandler))
}

func unbanUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := setUserBanned(r.Context(), id, false); err != nil {
		http.Error(w, "failed to unban user", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

## Explanation

`exportUsersHandler` was registered directly (`mux.HandleFunc("GET /admin/users/export", exportUsersHandler)`), bypassing the `requireAdmin` middleware that gates the other two admin routes in the same file. The fix wraps it identically to its siblings: `mux.HandleFunc("GET /admin/users/export", requireAdmin(exportUsersHandler))`. `requireAdmin` reads the authenticated user already placed on the request context by upstream session middleware and denies with 401 if absent or 403 if the caller's role isn't `"admin"`, before ever calling into `exportUsersHandler`. This closes the gap using the same centralized mechanism already used by `banUserHandler` and `unbanUserHandler`, rather than adding a new one-off check inside the handler body, and no new permission or role was introduced - the existing admin-only rule is simply applied to the route that was missing it. The doc comment on `RegisterRoutes` was updated to describe the corrected state (it previously stated, incorrectly, that only the ban/unban routes were wrapped).

## Behaviour changes

- `GET /admin/users/export` now returns `401 Unauthorized` for requests with no authenticated session, and `403 Forbidden` for an authenticated caller whose role is not `"admin"`, instead of `200` with the CSV body. This is the intended effect of the fix, not a side effect.
- No change to the route's success-path behavior for an authenticated admin caller: same status, headers, and CSV body as before.
- No other handler, signature, argument, or return value was altered. The only functional change is the single wrapping of `exportUsersHandler` in its registration call; the `RegisterRoutes` doc comment was updated to match.

Verification: `go build ./...` and `go vet ./...` both ran clean (exit code 0) against the fixed file in an isolated module, confirming the wrapped handler compiles and type-checks correctly (`requireAdmin` accepts an `http.HandlerFunc` and returns one, matching what `mux.HandleFunc`'s second argument expects).

Assumptions: none - the fix mirrors the wrapping pattern already present for the sibling ban/unban routes in the same file, per the loaded CWE-862 Go guidance ("wrap sensitive routes with a shared authorization middleware... rather than duplicating checks inline").
