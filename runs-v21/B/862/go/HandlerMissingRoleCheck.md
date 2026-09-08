## Verdict

Exploitable.

## Source

Authenticated user identity `caller` extracted from `context.Context` at line 48, containing the caller's Role field. The identity is verified as non-nil but the Role is never examined.

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

	// Check authorization - only admins can suspend user accounts.
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

The handler verified authentication (that a user is logged in) but never verified authorization (that the user is permitted to suspend accounts). The fix adds an explicit authorization check immediately after confirming the caller is authenticated: if `caller.Role` is not "admin", the handler returns HTTP 403 Forbidden and does not proceed to the sensitive operation. This prevents authenticated users without the admin role from reaching the `SuspendUser` sink, eliminating the missing authorization vulnerability. The check uses the same pattern as the authentication gate—an inline guard clause—and returns the appropriate HTTP status code for a permission denial on an authenticated request.

## Behaviour changes

None. The fix adds a gate that denies unprivileged requests before reaching the `SuspendUser` call; it does not alter the contract of that call (both original and fixed versions pass the same context and user ID, handle errors identically, and return the same HTTP status on success). Requests from admin users continue to proceed as before.
