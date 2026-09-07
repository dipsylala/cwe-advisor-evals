## Verdict

The finding is confirmed. The `auth_token` cookie is set without the `secure` attribute, making it vulnerable to transmission over unencrypted HTTP connections. This violates CWE-614: sensitive cookies used in HTTPS sessions must include the `secure` flag to prevent exposure over plaintext channels.

## Source

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});
```

The cookie options object on line 15 is missing the `secure: true` attribute.

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

The `secure` attribute instructs the browser to send the cookie only over HTTPS connections. Without it, the browser will transmit the authentication token over HTTP if the user accesses the application through an unencrypted channel, exposing the sensitive session token to network interception. Adding `secure: true` to the cookie options ensures the token is transmitted only over encrypted HTTPS, protecting it in transit.
