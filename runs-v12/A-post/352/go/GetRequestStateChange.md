## Verdict
Confirmed: CWE-352 (Cross-Site Request Forgery) vulnerability due to a state-changing operation exposed on an unsafe HTTP method without CSRF protection.

## Source
The vulnerability is on line 31 in `account_routes.go`:

```go
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
```

The account deletion endpoint is registered using the GET HTTP method. According to HTTP specifications, GET requests are intended to be safe (not causing state changes) and idempotent. The `http.CrossOriginProtection` middleware only validates non-safe methods (POST, PUT, DELETE, PATCH) and treats GET requests as safe by definition, so no origin or Sec-Fetch-Site validation is performed.

An attacker can trigger account deletion via a malicious site using an `<img>` tag, a simple link, or any other mechanism that causes a cross-origin GET request to this URL. The victim's browser automatically includes the session cookie, and the deletion proceeds without any CSRF token or origin check.

## Fix
Change line 31 from:
```go
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
```

To:
```go
mux.Handle("DELETE /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
```

This change makes two security improvements:
1. **Uses DELETE** instead of GET, semantically indicating a state-changing operation per HTTP standards
2. **Wraps with protection** using the `http.CrossOriginProtection` middleware, which validates the `Sec-Fetch-Site` header and rejects cross-origin deletion requests

## Explanation
The account deletion handler performs a destructive action (calling `store.Delete(userID)`). Exposing this on GET violates the principle that GET requests should be safe and cacheable. By changing to DELETE and enabling CrossOriginProtection validation, the endpoint becomes protected against CSRF attacks.

The `http.CrossOriginProtection` middleware uses Fetch metadata headers (`Sec-Fetch-Site`) to determine whether a request originated from the same site. Cross-origin requests with non-safe methods are rejected automatically. This is the same protection mechanism already applied to the `POST /account/email` and `PUT /account/password` endpoints on lines 25-26.

Clients making legitimate requests to delete the account should use the DELETE method and send the request via mechanisms that support custom HTTP methods (e.g., fetch API with `method: 'DELETE'`, or XMLHttpRequest). A convenience link (as mentioned in the comment) is no longer appropriate for this endpoint; instead, deletion should be triggered by an explicit user action through a form or button with JavaScript, ensuring both method correctness and origin validation.
