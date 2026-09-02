## Verdict

CSRF vulnerability confirmed. The `/settings/email` endpoint performs a state-changing operation but is registered on an unprotected mux, bypassing CSRF defences.

## Source

In `settings_routes.go` line 7, the `UpdateEmail` handler is registered on `apiMux`:

```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

The `UpdateEmail` handler (in `settings_handler.go` lines 13-22) performs a state-changing operation (`QueueEmailChange`) without CSRF token validation. By registering on `apiMux` instead of `protectedMux`, the endpoint is exposed without the CSRF middleware protection that `protectedMux` provides.

## Fix

Register the `/settings/email` endpoint on `protectedMux` to apply CSRF protection:

```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

## Explanation

State-changing operations (POST, PUT, DELETE) must be protected against CSRF attacks. The application separates protected routes (those with CSRF middleware) onto `protectedMux` and unprotected routes onto `apiMux`. The vulnerability arises from registering `UpdateEmail` on the wrong mux.

The email change operation at line 20 of `settings_handler.go` (`h.Service.QueueEmailChange()`) modifies user state and has no CSRF token validation. Moving the handler to `protectedMux` ensures the CSRF middleware intercepts requests and validates tokens before the handler executes, preventing cross-site forged requests from changing a user's email address.
