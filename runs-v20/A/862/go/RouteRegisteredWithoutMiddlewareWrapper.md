## Verdict

Confirmed. `RegisterRoutes` registers `GET /admin/users/export` with the bare `exportUsersHandler`, skipping the `requireAdmin` wrapper that every other admin route uses. Any caller, authenticated or not, can hit this route and receive a CSV dump of every user's id, email, and role - a missing authorization check on a route at least as sensitive as the ban/unban endpoints, which are correctly wrapped.

## Source

The request itself is the source: an unauthenticated `GET /admin/users/export` reaches `exportUsersHandler` because the route was registered without `requireAdmin(...)`, so `currentUser`/role checks never run before the handler executes.

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
// discloses the full user table to whoever can reach the route, so it is
// registered through requireAdmin in RegisterRoutes below.
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

// RegisterRoutes wires the admin handlers onto the mux. Every admin route,
// including exportUsersHandler, is wrapped with requireAdmin so only callers
// whose session user has the admin role can reach them.
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

`requireAdmin` already implements the correct authorization check - it reads the session user placed on the request context by upstream middleware and rejects with 401 when there is no authenticated user or 403 when the role is not `admin`. That check only runs when a handler is registered as `requireAdmin(handler)`; `mux.HandleFunc` has no way to apply it after the fact, so a route registered with the bare handler bypasses the check entirely regardless of what the handler itself does.

`exportUsersHandler` was registered directly (`mux.HandleFunc("GET /admin/users/export", exportUsersHandler)`), so the fix wraps it the same way the ban and unban routes already are: `requireAdmin(exportUsersHandler)`. This closes the gap using the existing, already-correct authorization mechanism rather than introducing a new one, keeps the fix at the single call site where the omission occurred, and requires no change to `requireAdmin`, `currentUser`, or the handler's own logic. No test in this sample exercises `RegisterRoutes` directly; verification is that the route registration line now matches the pattern used by every other admin route in the file.
