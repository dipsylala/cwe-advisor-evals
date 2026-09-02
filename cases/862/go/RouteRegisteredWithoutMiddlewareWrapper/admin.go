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
// was added later for a reporting integration and was registered directly,
// without the same requireAdmin wrapper, even though exporting the full
// user table is at least as sensitive as banning a single account.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/users/ban", requireAdmin(banUserHandler))
	mux.HandleFunc("POST /admin/users/unban", requireAdmin(unbanUserHandler))

	// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
	mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
}

func unbanUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := setUserBanned(r.Context(), id, false); err != nil {
		http.Error(w, "failed to unban user", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
