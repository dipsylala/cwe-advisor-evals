## Verdict

CWE-862 confirmed. The handler verifies the caller is authenticated but does not verify they possess admin privileges before performing the privileged operation of suspending a user account.

## Source

The vulnerability is at line 65 in `handler.go`. The `SuspendUserHandler` checks authentication at lines 48–52 but proceeds directly to call `h.Accounts.SuspendUser()` without verifying the caller holds the admin role required for that operation. Any authenticated user, regardless of role, can suspend arbitrary accounts.

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

	// Verify the caller has admin privileges.
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

The fix adds an explicit role-based authorization check immediately after authentication succeeds. Before calling the privileged `SuspendUser` operation, the handler now verifies that `caller.Role == "admin"`. If the authenticated caller lacks admin privileges, the handler returns a 403 Forbidden response and does not proceed to the sink.

This separates the two distinct security concerns:
- Authentication (lines 48–52): Proves the caller is logged in.
- Authorization (lines 55–58): Proves the caller has the required admin role for this operation.

The check guards the privileged sink at line 65 and prevents privilege escalation by non-admin users.
