## Verdict

Exploitable. CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute).

- Location: `ExpressCookieNoSecureFlag.js:15`
- Confidence: high

## Source

`req.query.token` (line 8) - the signed authentication token the SSO provider hands back as a query parameter on the callback redirect. That value flows directly into the `res.cookie('auth_token', authToken, ...)` call at line 15, which sets it as the session's auth cookie. The options object passed to `res.cookie()` contains `httpOnly: true` and `maxAge: 86400000` but omits `secure`, whose default is `false` - so Express will happily emit the `Set-Cookie` header on a plain-HTTP response, and the auth token then travels in the clear on any subsequent request the browser makes over HTTP, exposed to network interception and session hijacking.

## Fix

```javascript
// Vulnerable
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});

// Fixed
res.cookie('auth_token', authToken, {
  httpOnly: true,
  secure: true,
  maxAge: 86400000,
});
```

No third-party library is needed; `secure` is a native `res.cookie()` option in Express.

## Explanation

Adding `secure: true` instructs Express to mark the `Set-Cookie` header with the `Secure` attribute, so the browser will only ever attach `auth_token` to requests made over HTTPS and will refuse to send it over plain HTTP. This directly closes the CWE-614 weakness: the sensitive SSO-issued auth token can no longer be transmitted or replayed over an unencrypted connection. `httpOnly: true` was already present and is left unchanged. The fix assumes the application is served over HTTPS in production (this file has no visible app/server bootstrap to confirm that, or any reverse-proxy `trust proxy` configuration); if the app is not fully HTTPS-enforced, `secure: true` cookies will simply never be set by the browser's own request path over HTTP, which will surface as broken session persistence rather than as an insecure cookie - HTTPS enforcement should be verified separately.

## Behaviour changes

- Added `secure: true` to the cookie options. This is the required fix for CWE-614 and is the only change made. Consequence: the cookie will not be sent by the browser on any HTTP (non-TLS) request, which is the intended, security-mandated effect.
- No other cookie attributes (`httpOnly`, `maxAge`), the token value, the response redirect, or any other code path were modified. `sameSite` was left untouched since this finding concerns only the missing `Secure` attribute (CWE-614), not CSRF handling (CWE-352); adding it here would be scope creep beyond the reported finding.
