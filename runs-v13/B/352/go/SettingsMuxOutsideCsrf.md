## Verdict

Exploitable. The `/settings/email` endpoint performs a state-changing POST operation (email modification via `QueueEmailChange`) without CSRF token validation because it is registered on an unprotected `apiMux` rather than the CSRF-protected `protectedMux`.

## Source

HTTP request received by the unauthenticated `apiMux` router, routed to `UpdateEmail` handler, which extracts email from `r.FormValue("email")` at settings_handler.go line 16.

## Fix

**Vulnerable code:**
```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	apiMux.HandleFunc("/settings/email", handler.UpdateEmail)  // Line 7: state-changing handler on unprotected mux
}
```

**Fixed code:**
```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)  // State-changing handler now on CSRF-protected mux
}
```

## Explanation

The `UpdateEmail` handler accepts POST requests that mutate server state (queuing an email change). Per CWE-352 and Go guidance, all state-changing routes must be registered on a CSRF-protected router to validate synchronizer tokens before processing the request. The vulnerable code registers this state-changing endpoint on `apiMux`, which has no CSRF protection, allowing forged cross-site requests to modify user email addresses. Moving the registration to `protectedMux` ensures the endpoint is wrapped by CSRF middleware, which validates the token before the handler runs, eliminating the vulnerability.

## Behaviour changes

None. The fix preserves the handler's contract: it still accepts POST requests to `/settings/email`, validates the HTTP method, extracts the email parameter, and calls `QueueEmailChange`. The only difference is that the route is now protected by CSRF token validation, which is a security improvement without functional side effects for legitimate requests that include the required token.
