## Verdict

exploitable

## Source

HTTP POST request to `/account/settings` handler:
- Untrusted request body decoded at line 68: `settingsUpdateRequest` containing `Email` and `DisplayName` fields
- Authenticated session extracted from cookie at line 61: `accountID` 
- Current protection relies solely on Origin header presence/value match at line 56, which is insufficient for CSRF defense

## Fix

**Vulnerable code (line 29-31):**
```go
func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	mux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
}
```

And handler at lines 35-43 performs only Origin header validation:
```go
func isTrustedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == appHost
}
```

**Fixed code:**
```go
func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	router := http.NewServeMux()
	router.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
	protected := http.CrossOriginProtection(router)
	mux.Handle("/", protected)
}
```

Remove the `isTrustedOrigin()` function and origin validation from the handler (lines 35-43 and line 56-59 can be deleted).

The `UpdateSettingsHandler` function simplified (lines 50-80):
```go
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	accountID, ok := accountIDFromSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req settingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.store.UpdateSettings(accountID, req.Email, req.DisplayName); err != nil {
		http.Error(w, "failed to update settings", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

## Explanation

`net/http.CrossOriginProtection` (available in Go 1.25.1+) validates state-changing requests using Fetch metadata headers (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`), which browsers attach automatically to same-site requests and which cannot be overridden by JavaScript from a cross-origin context. This provides CSRF protection at the middleware level, preventing forged cross-site POST requests from reaching the handler. The Origin header alone is insufficient because it can be absent in certain request types and, when present, is not reliably verified server-side as the sole defense. By wrapping the state-changing route with `CrossOriginProtection`, all requests to `/account/settings` must pass Fetch metadata validation before the handler executes, eliminating the CSRF attack surface that relied on the Origin header check alone.

## Behaviour changes

The fix changes the router registration structure: instead of directly registering handlers on the passed-in mux, a separate router is created, wrapped with CSRF protection, and attached to the mux. This ensures all state-changing routes go through the protection middleware. The Origin header validation is removed from the handler logic, shifting CSRF defense from application code to the middleware layer. The overall handler behavior remains the same for legitimate requests that pass Fetch metadata validation—only requests that fail CSRF validation (cross-origin state-changing requests) are rejected with an automatic 403 response from the middleware before reaching the handler. If older Go versions (pre-1.25.1) are required, use `filippo.io/csrf/gorilla` as a drop-in middleware wrapper with the same registration pattern.
