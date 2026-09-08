## Verdict
Confirmed. `SuspendUserHandler` verifies the caller is authenticated (a valid `*User` is present in the request context) but never checks that the caller is authorized to suspend accounts. Any logged-in user, regardless of role, can call this admin-only endpoint and disable an arbitrary account by `user_id`.

## Source
- `caller, ok := r.Context().Value(userContextKey).(*User)` (line 48) - the authenticated caller, including its `Role` field, resolved by upstream session middleware.
- `req.UserID` (line 34/59) - attacker-controlled target account ID from the JSON request body.

## Fix

### File: handler.go
```go
package admin

import (
	"context"
	"encoding/json"
	"net/http"
)

type contextKey string

// userContextKey is where the session middleware stores the authenticated
// caller after validating their cookie/JWT earlier in the chain.
const userContextKey contextKey = "authenticatedUser"

// User is the authenticated caller resolved from the session store.
type User struct {
	ID    string
	Email string
	Role  string
}

// AccountService performs account lifecycle operations against the store.
type AccountService interface {
	SuspendUser(ctx context.Context, targetUserID string) error
}

// AdminHandler exposes account-management endpoints intended for
// administrators only.
type AdminHandler struct {
	Accounts AccountService
}

type suspendUserRequest struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

// SuspendUserHandler handles POST /admin/users/suspend. It disables the
// target account so the user can no longer authenticate.
func (h *AdminHandler) SuspendUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Confirm the request is authenticated - this only proves the caller is
	// *someone*, not that they are permitted to suspend other accounts.
	caller, ok := r.Context().Value(userContextKey).(*User)
	if !ok || caller == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Authorization check: only administrators may suspend accounts. Being
	// authenticated is not sufficient - this endpoint is admin-only.
	if caller.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req suspendUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	if err := h.Accounts.SuspendUser(r.Context(), req.UserID); err != nil {
		http.Error(w, "failed to suspend user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

## Explanation
The handler's only gate was authentication (`ok || caller == nil`), which establishes identity but not permission. The fix adds an explicit authorization check on `caller.Role` immediately after authentication and before any request parsing or the `SuspendUser` sink, rejecting non-admin callers with `403 Forbidden`. This follows the existing `User.Role` field already present on the authenticated caller, so no new dependency, session data, or schema change is required - the role was already being resolved by the session middleware and simply wasn't consulted. Checking authorization before decoding the body also avoids doing unnecessary work (and exposing body-parsing error details) to a caller who isn't allowed to invoke the endpoint at all.
