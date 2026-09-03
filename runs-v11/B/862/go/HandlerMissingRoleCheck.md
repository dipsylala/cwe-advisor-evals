## Verdict
exploitable

## Source
`req.UserID` from JSON request body (parsed at lines 54-62)

## Fix

**Vulnerable code (line 40-71, focusing on the authorization gap):**
```go
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

	var req suspendUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	// MISSING: Authorization check for admin role
	if err := h.Accounts.SuspendUser(r.Context(), req.UserID); err != nil {
		http.Error(w, "failed to suspend user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

**Fixed code:**
```go
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

	// Authorization check: only admins may suspend users
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

The handler authenticates the caller (lines 48-52) but never verifies they hold the required authorization to suspend user accounts. The fix adds an explicit role check immediately after authentication: if the caller is not an admin, the handler returns 403 Forbidden. This ensures only administrators can invoke the sensitive `SuspendUser` operation. The check uses the authenticated user's `Role` field, which was populated earlier by session middleware, and applies the centralized pattern: an early guard clause that fails closed (denies by default) before any sensitive operation executes.

## Behaviour changes

The handler now returns 403 (Forbidden) for authenticated users lacking the admin role, where it previously would have proceeded to suspend their target account. This is the intended new behavior that closes the authorization gap. No other behavior changes: successful calls from authorized admins remain unchanged, authentication failures still return 401, request validation still returns 400, and success still returns 204.
