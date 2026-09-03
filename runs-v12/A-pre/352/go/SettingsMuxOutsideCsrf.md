## Verdict
VULNERABLE - Cross-Site Request Forgery

## Source
Line 7 in settings_routes.go:
```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

The `/settings/email` route is registered on `apiMux` rather than `protectedMux`. The corresponding handler accepts POST requests with form data and performs a state-changing operation (email change) without CSRF token validation.

## Fix
Change line 7 to register the route on the protected mux:

```go
protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

## Explanation
The vulnerability occurs because the `/settings/email` endpoint is registered on `apiMux` instead of `protectedMux`. The UpdateEmail handler modifies sensitive user account information by accepting a new email address via POST and queuing an email change without validating a CSRF token.

An attacker can exploit this by:
1. Crafting a cross-site request to POST /settings/email with a malicious email value
2. Tricking a victim into visiting a page containing this request (either as a form submission or image src)
3. Since there is no CSRF token validation and the route is not on the protected mux, the attacker's email address is queued for the victim's account

Registering the route on `protectedMux` ensures that any CSRF protection middleware applied to that mux will guard this state-changing operation, preventing the forgery.
