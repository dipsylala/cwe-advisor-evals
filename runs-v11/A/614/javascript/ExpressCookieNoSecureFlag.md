## Verdict

**CONFIRMED.** The authentication token cookie is set without the `secure` attribute, allowing transmission over unencrypted HTTP if the user is downgraded to or navigates over HTTP.

## Source

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});
```

Line 15–18. The cookie stores a sensitive SSO token but lacks the `secure` flag.

## Fix

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  secure: true,
  maxAge: 86400000,
});
```

Add `secure: true` to the cookie options.

## Explanation

When `secure: true` is set, the browser transmits the cookie only over HTTPS, blocking interception on unencrypted channels. The `httpOnly` flag already prevents JavaScript access; `secure` closes the transport-layer risk. In production, HTTPS is standard for authenticated endpoints. This flag ensures the cookie is never exposed in transit, even if a user is briefly downgraded or a network redirect occurs.
