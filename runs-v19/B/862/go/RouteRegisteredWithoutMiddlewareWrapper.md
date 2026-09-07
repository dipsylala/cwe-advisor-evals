## Verdict

CONFIRMED. The route handler `exportUsersHandler` is registered on line 103 without the `requireAdmin` authorization middleware that guards other admin routes. Any authenticated user, regardless of role, can call `GET /admin/users/export` and receive the full user table including email addresses. The vulnerability is an implementation of Missing Authorization at the route registration layer, not inside the handler itself.

## Source

**File:** `admin.go`

**Line 103 (sink):** `mux.HandleFunc("GET /admin/users/export", exportUsersHandler)`

**Handler definition (lines 66-82):** `exportUsersHandler` returns sensitive data (all user records including email addresses) without any authorization check.

**Reference pattern (lines 99-100):** Other admin routes (`POST /admin/users/ban`, `POST /admin/users/unban`) are correctly registered with the `requireAdmin` middleware wrapper.

**Data flow:** Route registration → Handler execution → CSV export of all users. Authorization check is bypassed entirely.

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

// RegisterRoutes wires the admin handlers onto the mux. banUserHandler is
// wrapped with requireAdmin so only admins can reach it. exportUsersHandler
// was added later for a reporting integration and is now wrapped with
// requireAdmin to enforce the same authorization as other admin routes.
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

The vulnerability is that line 103 registers `exportUsersHandler` directly to the mux without wrapping it in the `requireAdmin` middleware. While the handler itself does not perform any inline authorization checks, the Go pattern used here enforces authorization at the routing layer through middleware wrapping. Lines 99-100 show the correct pattern: both the ban and unban handlers are wrapped with `requireAdmin` at registration time. The fix applies the same wrapper to the export route, ensuring that `requireAdmin` middleware runs before `exportUsersHandler` executes. This matches the centralized authorization pattern already established in the codebase and closes the gap that allows an authenticated user with any role to access sensitive user data.

The `requireAdmin` middleware already exists and is correctly implemented - it checks for authentication (returns 401 if missing) and then checks for the admin role (returns 403 if the caller lacks it). Applying it here requires no changes to middleware logic, only to the route registration.

## Behaviour changes

- **Before fix:** Any authenticated user can call `GET /admin/users/export` and receive a CSV file containing all user records including email addresses, regardless of their role.
- **After fix:** Only authenticated users with the `admin` role can call `GET /admin/users/export`. Unauthenticated requests receive `401 Unauthorized`. Authenticated users lacking the admin role receive `403 Forbidden`. The export succeeds only when both authentication and authorization checks pass.
