## Verdict

Exploitable. `SuspendUserHandler` confirms the request carries a valid session (authentication) but never checks the caller's role before invoking the sink, so any authenticated user - not just an administrator - can suspend any other account by supplying its `user_id`.

## Source

`r.Context().Value(userContextKey).(*User)` at line 48 - the authenticated caller resolved by upstream session middleware, and `req.UserID` decoded from the request body at line 54, naming the target account.

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

	// Authorization check: this endpoint is admin-only. Authentication above
	// only established who the caller is, not that they may suspend other
	// accounts, so the role must be checked explicitly and the request
	// denied (fail closed) for anyone who is not an admin.
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

The handler authenticated the caller but never asked whether that caller was permitted to suspend accounts, so the missing check - not the authentication step - was the gap. The fix adds an explicit role check (`caller.Role != "admin"`) immediately after the existing authentication check and before any request parsing or the `SuspendUser` sink, denying with `403 Forbidden` (the caller is known and simply not permitted, distinct from the `401` used above it for an unauthenticated caller) and failing closed for any role value other than `"admin"`, including an empty one. `SuspendUserHandler` is documented as an administrator-only endpoint and `User.Role` already exists on the struct populated by upstream session middleware, so the check enforces the permission the handler was already supposed to require rather than inventing a new one. This targets a specific target account by ID rather than the caller's own resource, so this is an action-level (role) check, not an ownership check - CWE-862's resource-ownership pattern does not apply here.

## Behaviour changes

- Added: a `403 Forbidden` response for any authenticated caller whose `Role` is not `"admin"`, where the request previously succeeded (`204 No Content`) regardless of role. This is the intended effect of the fix, not a side effect.
- No other request handling, argument, return value, or error path was changed. The `401` path, body validation, decode-error handling, and the `SuspendUser` call and its arguments are unchanged.

Assumption: the admin role is identified by the literal string `"admin"` on `User.Role`. No role-constant or enum was visible in the single-file call chain provided; if the codebase defines a shared role constant elsewhere, the check should reference that constant instead of the literal.

Verification: `go vet ./...` and `go build ./...` against the fixed file in a scratch module (Go 1.25.5) both completed with exit code 0 and no diagnostics.
