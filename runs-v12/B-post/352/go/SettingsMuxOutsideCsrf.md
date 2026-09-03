## Verdict

Exploitable. The `UpdateEmail` handler performs a state-changing operation (POST request that queues an email change) but is registered on the unprotected `apiMux` instead of the CSRF-wrapped `protectedMux`. This allows an attacker to forge a cross-site request that modifies the user's email without the user's knowledge.

## Source

HTTP POST request to `/settings/email` endpoint received by the web server from any origin.

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

State-changing handlers must be registered on a CSRF-protected router. The `UpdateEmail` handler accepts POST requests and calls `h.Service.QueueEmailChange()` to mutate user state by changing their email address. According to Go CWE-352 guidance, "Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux." The fix moves the route registration from `apiMux` to `protectedMux`, ensuring that the handler is protected by whatever CSRF middleware wraps the protected mux (such as `net/http.CrossOriginProtection` on Go 1.25.1+ or `filippo.io/csrf/gorilla` on older releases).

## Behaviour changes

None. Moving a route from one mux to another does not alter the handler's logic or output. Both muxes are assumed to be configured as their names suggest, with `protectedMux` wrapped by CSRF middleware and `apiMux` used for other endpoints. If both muxes are currently unprotected, this fix must be accompanied by wrapping the `protectedMux` with CSRF middleware to be effective.
