## Verdict

CONFIRMED. The handler verifies the caller is authenticated (line 48-52) but never checks whether they hold the "admin" role or permission required to suspend accounts. Any authenticated user can invoke `SuspendUser` on line 65, making this a missing authorization check on a sensitive action.

## Source

Line 48-52: Authenticated user extracted from context:
```
caller, ok := r.Context().Value(userContextKey).(*User)
if !ok || caller == nil {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
```

The caller's role is available in `caller.Role` but is never consulted.

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

	// Verify the caller has admin role (authorization check).
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

	// Now safe to call - caller has been verified as admin.
	if err := h.Accounts.SuspendUser(r.Context(), req.UserID); err != nil {
		http.Error(w, "failed to suspend user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

## Explanation

The fix adds an explicit authorization check immediately after authentication verification (lines 56-59). Before calling the sensitive `SuspendUser` operation, the handler now verifies that `caller.Role` equals `"admin"`. If the check fails, the handler returns `http.StatusForbidden` (403), which correctly indicates an authenticated caller lacking permission—distinct from `401 Unauthorized` which indicates a missing or invalid identity.

This separates authentication (verifying who the caller is) from authorization (verifying what they are allowed to do), following CWE-862 guidance. The fix preserves the existing semantics: the operation still targets the specified user ID, but now only admin-role users can invoke it. The role comparison assumes the application's role model stores "admin" as the required role value for this endpoint; this aligns with the handler's documentation stating it "exposes account-management endpoints intended for administrators only."

## Behaviour changes

- Returns 403 Forbidden when an authenticated but non-admin user calls the endpoint
- Original: any authenticated user could suspend any account
- Fixed: only users with `Role == "admin"` can execute account suspension
- Response status code and body change from 200 NoContent to 403 Forbidden for unprivileged callers
