## Verdict

Authorization bypass: the endpoint verifies authentication (that the caller is *someone*) but does not verify authorization (that the caller has permission to perform this action). Any authenticated user can suspend other accounts.

## Source

Lines 48-68 show the vulnerability. After confirming authentication (lines 48-52), the handler does not check the caller's role before calling `h.Accounts.SuspendUser()` at line 65. The comment at lines 46-47 explicitly identifies this gap: "this only proves the caller is *someone*, not that they are permitted to suspend other accounts."

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

	// Verify the caller has admin role before allowing this action.
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

	// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
	if err := h.Accounts.SuspendUser(r.Context(), req.UserID); err != nil {
		http.Error(w, "failed to suspend user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

## Explanation

The fix adds an explicit role check at lines 61-64, immediately after authentication succeeds. The caller's role is compared against the required role ("admin"). If the role does not match, the handler returns HTTP 403 Forbidden and does not proceed to `SuspendUser()`.

This enforces the principle of least privilege: authentication alone is not sufficient for privileged operations. Authorization—verifying that the caller holds the required role—must happen before the sensitive operation executes.

