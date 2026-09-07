## Verdict

This is a confirmed CSRF vulnerability. The `/settings/email` endpoint modifies user state (queues an email change) via HTTP POST but is registered on an unprotected multiplexer (`apiMux`) instead of the CSRF-protected multiplexer (`protectedMux`). An attacker can forge a cross-site request to change a user's email address without the user's knowledge or consent.

## Source

The vulnerability exists in `settings_routes.go` line 7:

```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

The `UpdateEmail` handler (in `settings_handler.go`) accepts POST requests and modifies state by calling `h.Service.QueueEmailChange(r.Context(), email)` without validating a CSRF token. Because this route is registered on the unprotected `apiMux` instead of the CSRF-protected `protectedMux`, no CSRF middleware validates the request origin.

## Fix

Change line 7 in `settings_routes.go` from:

```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

to:

```go
protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

This registers the state-modifying endpoint on the CSRF-protected multiplexer, ensuring that CSRF middleware will validate the request token before the handler executes.

## Explanation

The application distinguishes between two multiplexers: `protectedMux` (which has CSRF middleware) and `apiMux` (which does not). The `/settings/email` endpoint performs a state-changing operation (queuing an email change) in response to POST requests, which makes it a state-modifying sink that must be protected against CSRF.

By registering the route on `protectedMux`, the endpoint becomes subject to CSRF token validation. The handler can then assume incoming requests have passed the CSRF check before processing the email change request. This prevents attackers from crafting malicious cross-site requests that exploit the victim's browser session to modify their settings.
