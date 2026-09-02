## Verdict

Exploitable. The authentication token cookie is set without the `secure` flag, allowing it to be transmitted over unencrypted HTTP connections and exposed to interception.

## Source

`req.query.token` (line 8) — attacker-controlled query parameter passed by the SSO provider containing a signed session token.

## Fix

**Vulnerable code:**
```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});
```

**Fixed code:**
```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 86400000,
});
```

## Explanation

The `secure: true` flag ensures the cookie is only transmitted over HTTPS connections, preventing man-in-the-middle interception of the authentication token. The `sameSite: 'lax'` attribute mitigates CSRF attacks while permitting the cookie to be sent on the cross-site SSO redirect (unlike `strict`, which would withhold it and break the authentication flow). Combined with the existing `httpOnly: true`, this protects the cookie against both network-level attacks and XSS-based theft. Ensure the application enforces HTTPS in production for the flag to function.

## Behaviour changes

- Adds `secure: true` to restrict cookie transmission to HTTPS only.
- Adds `sameSite: 'lax'` to provide CSRF protection while allowing SSO redirect flows.
- No changes to cookie name, value, maxAge, httpOnly, return values, or error handling. The cookie is still set identically; only the transmission rules are strengthened.
