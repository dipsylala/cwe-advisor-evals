## Verdict
Exploitable

## Source
The authenticated user's role is read from `caller.Role` (line 48), extracted from the context after session validation.

## Fix

**Vulnerable code:**
```go
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

// VULNERABILITY: No authorization check before calling SuspendUser
if err := h.Accounts.SuspendUser(r.Context(), req.UserID); err != nil {
    http.Error(w, "failed to suspend user", http.StatusInternalServerError)
    return
}
```

**Fixed code:**
```go
// Confirm the request is authenticated - this only proves the caller is
// *someone*, not that they are permitted to suspend other accounts.
caller, ok := r.Context().Value(userContextKey).(*User)
if !ok || caller == nil {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}

// Check authorization: only admins may suspend users
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
```

## Explanation
The handler verifies that a request is authenticated (the caller is logged in) but does not verify that the caller is authorized to perform the action (suspends other user accounts). The fix adds an explicit role check immediately after authentication: if the caller's role is not "admin", the handler returns 403 Forbidden and does not proceed to call `SuspendUser()`. This follows CWE-862 remediation by separating authentication (who is the caller) from authorization (what the caller may do) and enforcing the required permission before the sensitive operation executes.

## Behaviour changes
None. The handler continues to return 401 for missing authentication and now returns 403 for authenticated but unauthorized callers, both documented as correct responses in the Go guidance. The existing response codes and call paths for valid authorization remain unchanged.
