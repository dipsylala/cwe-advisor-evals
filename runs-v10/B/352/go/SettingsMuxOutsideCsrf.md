## Verdict

Exploitable. The `UpdateEmail` handler performs state-changing operations (POST) but is registered on an unprotected mux, bypassing CSRF protection entirely.

## Source

HTTP POST request to `/settings/email` carrying an email parameter via `r.FormValue("email")`.

## Fix

**Vulnerable code** (settings_routes.go, line 7):
```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

**Fixed code**:
```go
protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

## Explanation

The `UpdateEmail` handler accepts POST requests and modifies server state by queuing an email change via `h.Service.QueueEmailChange(r.Context(), email)`. Registering this state-changing handler on `apiMux` (an unprotected mux) instead of `protectedMux` (a CSRF-protected mux) leaves it vulnerable to cross-site request forgery attacks. An attacker can craft a malicious request that tricks an authenticated user into changing their email without their knowledge. Moving the registration to `protectedMux` ensures the handler receives CSRF middleware validation before processing any request, blocking forged cross-origin state changes.

## Behaviour changes

None. The fix preserves the handler contract: it still processes POST requests, reads the email parameter, and calls the service method. Only the security wrapper (CSRF protection) changes; the application behavior remains identical for legitimate requests.
