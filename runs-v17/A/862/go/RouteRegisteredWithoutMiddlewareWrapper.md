## Verdict
CWE-862 (Missing Authorization) confirmed. The `exportUsersHandler` route at line 103 is registered without the `requireAdmin` middleware, allowing unauthenticated or non-admin users to access sensitive admin functionality that exports all user data.

## Source
Line 103 in `RegisterRoutes()`:
```
mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
```

The route handler exports the complete user table including email addresses (lines 63-82), which is as sensitive as the ban/unban operations, yet it lacks the authorization check present in lines 99-100.

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
// requireAdmin, just like other sensitive admin routes.
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
The fix wraps `exportUsersHandler` with the `requireAdmin` middleware at line 103, enforcing the same authorization check applied to other sensitive admin operations. This ensures only authenticated users with the "admin" role can access the endpoint.

The middleware verifies the authenticated user exists in the request context and has the "admin" role; unauthenticated requests receive a 401 Unauthorized response, and authenticated non-admin users receive a 403 Forbidden response. This prevents unauthorized disclosure of the complete user table.

The change also updates the RegisterRoutes comment to reflect that both ban/unban and export operations are now protected by the same authorization control.
