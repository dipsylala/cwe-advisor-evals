## Verdict

The finding is accurate. Line 15 sets a sensitive authentication cookie without the `secure` flag, allowing transmission over non-HTTPS connections.

## Source

Line 15-18 in ExpressCookieNoSecureFlag.js:
```javascript
res.cookie('auth_token', authToken, {
    httpOnly: true,
    maxAge: 86400000,
});
```

The cookie stores a sensitive SSO authentication token but omits the `secure` option, which is required to restrict transmission to HTTPS-only connections.

## Fix

Add `secure: true` to the cookie options:

```javascript
res.cookie('auth_token', authToken, {
    httpOnly: true,
    secure: true,
    maxAge: 86400000,
});
```

## Explanation

The `secure` flag restricts the cookie to HTTPS connections only, preventing the browser from transmitting it over plaintext HTTP. Without it, an attacker on a network path can intercept the authentication token through a downgrade attack or man-in-the-middle capture. Setting `secure: true` alongside the already-present `httpOnly: true` provides defense-in-depth: `httpOnly` prevents client-side script access, while `secure` prevents network interception of the session credential.
