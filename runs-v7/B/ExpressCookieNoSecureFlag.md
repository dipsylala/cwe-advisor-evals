## Verdict

**Confirmed.** The auth_token cookie is set without the `secure` flag, making it transmissible over unencrypted HTTP connections and vulnerable to interception via man-in-the-middle attacks, network sniffing, and session hijacking.

## Source

Line 8: `authToken` extracted from `req.query.token` (attacker-controlled).
Line 15: Sink is `res.cookie('auth_token', authToken, {...})`.
The untrusted token flows directly to the cookie-setting operation without validation beyond a null-check.

## Fix

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
  secure: true,
});
```

Add `secure: true` to the options object. Optionally add `sameSite: 'lax'` for CSRF protection (recommended for SSO callbacks, since `Strict` would block the inbound redirect from the SSO provider).

## Explanation

The `secure` flag restricts cookie transmission to HTTPS connections only. Without it, Express transmits the cookie over both HTTP and HTTPS, exposing it to interception. Adding `secure: true` ensures the sensitive auth_token is only sent over encrypted channels, eliminating the transmission vulnerability. The existing `httpOnly: true` prevents JavaScript access, which is already correct.

## Behaviour changes

**Production (HTTPS-only)**: No visible change for legitimate users; cookies are transmitted as before, now with transport-layer protection.

**If accessed over HTTP**: Browsers will not receive or send the cookie over HTTP, causing authentication to fail silently. This is correct behavior—the application should enforce HTTPS in production. Verify that:
- HTTPS is enforced site-wide (e.g., via redirect middleware or infrastructure)
- Any reverse proxy between client and app has `app.set('trust proxy', true)` configured so Express correctly detects HTTPS

**Testing**: Confirm in a production-like environment that the Set-Cookie header includes `Secure` and that the cookie is not transmitted over HTTP.
