## Verdict
exploitable

## Source
Attacker-crafted cross-site request to a state-changing endpoint lacking CSRF validation

## Fix

**Vulnerable code:**
```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	apiMux.HandleFunc("/settings/email", handler.UpdateEmail)  // CSRF-unprotected sink
}
```

**Fixed code:**
```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

## Explanation
The `UpdateEmail` handler accepts POST requests and mutates state by calling `h.Service.QueueEmailChange`, making it a state-changing endpoint. It was registered on `apiMux`, a separate mux outside CSRF protection. The fix moves the route registration from `apiMux` to `protectedMux`, ensuring the endpoint is wrapped by the CSRF validation middleware and can validate tokens before processing requests.

## Behaviour changes
none
