## Verdict

Exploitable. The handler verifies the caller is authenticated (logged in) but never checks whether they hold the authorization to suspend user accounts. Any authenticated user, regardless of role, can suspend any target account by invoking this endpoint.

## Source

The untrusted input is `req.UserID` from the POST request body (decoded at line 55), passed directly to `h.Accounts.SuspendUser()` without authorization validation.

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

	// Check authorization: only admins may suspend accounts.
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

	// Perform the sensitive operation now that authorization is confirmed.
	if err := h.Accounts.SuspendUser(r.Context(), req.UserID); err != nil {
		http.Error(w, "failed to suspend user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

## Explanation

The fix adds an explicit role-based authorization check after authentication, immediately after confirming the caller's identity. The handler now returns `http.StatusForbidden` (403) if the authenticated user's role is not `"admin"`, preventing unauthorized account suspension. This follows the language guidance to add the check through the caller's role and to return 403 when authorization fails. The check runs before request parsing so invalid credentials are rejected before any work is done, and the response code distinguishes authorization failure (403) from missing credentials (401).

## Behaviour changes

- An authenticated non-admin user who attempts to call POST /admin/users/suspend now receives HTTP 403 Forbidden instead of a 204 No Content response. Previously, any authenticated user could suspend any account regardless of role.
- The endpoint now enforces role-based access control: only users with `Role == "admin"` may proceed. This is the intended authorization policy for an administrative capability.
- The response status code shift (200/204 → 403) for unauthorized callers allows clients and middleware to distinguish authorization denial from successful operations and from authentication failures.

