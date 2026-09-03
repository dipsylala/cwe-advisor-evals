## Verdict

CONFIRMED — The state-changing `UpdateEmail` handler is registered on an unprotected mux, bypassing CSRF protection.

## Source

**File:** evals/cases/352/go/SettingsMuxOutsideCsrf/settings_routes.go  
**Line:** 7  
**Vulnerable code:**
```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

The `UpdateEmail` handler accepts POST requests that modify user state (queuing an email change via `h.Service.QueueEmailChange(r.Context(), email)`). It is registered on `apiMux` rather than `protectedMux`, placing it outside any CSRF protection middleware that may wrap `protectedMux`.

## Fix

Register the state-changing handler on the CSRF-protected mux:

```go
protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

Replace line 7 with the above. This ensures the handler is wrapped by the same CSRF protection as other authenticated state-changing operations.

## Explanation

Go's `net/http` package provides no built-in CSRF protection; handlers must be explicitly wrapped with CSRF middleware (via `net/http.CrossOriginProtection` on Go 1.25.1+, `filippo.io/csrf/gorilla`, or framework-native middleware). The vulnerability arises when state-changing handlers are registered on a separate or unprotected mux, bypassing this middleware entirely.

The call chain shows:
1. `RegisterSettingsRoutes()` accepts two muxes: `protectedMux` (presumably CSRF-protected) and `apiMux` (unprotected)
2. `UpdateEmail` is a state-changing handler that reads form input (`r.FormValue("email")`) and invokes `h.Service.QueueEmailChange()` to mutate user state
3. Registering it on `apiMux` means attackers can forge cross-site POST requests that change a victim's email without a valid CSRF token

The fix ensures all state-changing operations—regardless of route—are validated by the same CSRF protection middleware.

## Behaviour changes

**Before:** Unauthenticated cross-origin POST requests to `/settings/email` succeed without CSRF validation, allowing account takeover.

**After:** POST requests to `/settings/email` are validated by CSRF middleware. Requests missing a valid token are rejected with HTTP 403 Forbidden before the handler logic runs. Legitimate form/AJAX requests that include the token succeed; forged cross-site requests fail.
