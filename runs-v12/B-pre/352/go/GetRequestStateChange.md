## Verdict

CONFIRMED. The state-changing operation (account deletion) is reachable via GET, which bypasses CSRF protection.

## Source

HTTP GET request to `/account/delete` initiated by a cross-origin context (e.g., malicious website embedding `<img src="https://target.com/account/delete">` or a link in an email).

## Fix

**Original (vulnerable):**
```go
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
```

**Fixed:**
```go
mux.Handle("DELETE /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
```

## Explanation

The vulnerability exists because the account deletion endpoint is exposed via GET, which is treated as a safe HTTP method by CSRF middleware. The `http.CrossOriginProtection` middleware only validates non-safe methods (POST, PUT, DELETE, PATCH) using Fetch metadata headers. By registering the endpoint on GET, the handler bypasses protection entirely—a cross-site `<img>` tag, bare link navigation, or email-embedded URL triggers account deletion with the victim's session cookie automatically attached and no origin check performed.

The fix moves the state-changing operation from GET to DELETE, which causes the `http.CrossOriginProtection` middleware to validate the `Sec-Fetch-Site` header. On a cross-origin request (attacker's website), this header will be missing or set to `cross-site`, and the middleware will reject the request with HTTP 403 before reaching the handler. Legitimate same-site requests from the application's own pages will include the correct header and pass validation.

## Behaviour changes

- Account deletion now requires DELETE method instead of GET
- Cross-origin requests to delete accounts are rejected with HTTP 403
- Same-origin requests from the application continue to work as before
- The operation is no longer exploitable via simple cross-site requests (images, links, form GET)
