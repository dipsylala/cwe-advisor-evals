## Verdict

**Confirmed**. The `auth_token` cookie at line 15 lacks the `secure` flag, allowing transmission over unencrypted HTTP and exposing the authentication token to interception.

## Source

**File**: `ExpressCookieNoSecureFlag.js`  
**Line**: 15  
**Sink**: `res.cookie('auth_token', authToken, {...})`  
**Issue**: Options object omits `secure: true`

## Fix

```javascript
res.cookie('auth_token', authToken, {
  secure: true,
  httpOnly: true,
  maxAge: 86400000,
});
```

Add `secure: true` to the cookie options. This ensures the browser only sends the cookie over HTTPS connections, preventing transmission on unencrypted HTTP.

## Explanation

The `authToken` is a sensitive session identifier returned from an SSO provider. Without the `secure` flag, Express will transmit the cookie over both HTTP and HTTPS. An attacker on an unencrypted connection can intercept it and hijack the authenticated session. Setting `secure: true` enforces that the browser only includes the cookie in HTTPS requests, mitigating man-in-the-middle attacks and network sniffing.

## Behaviour changes

- Cookies will only be transmitted over HTTPS. 
- In production, this is transparent: the application runs on HTTPS and cookies transmit normally.
- In development over HTTP, the secure cookie won't be sent by the browser, which may require local HTTPS setup or a proxy configuration (`app.set('trust proxy', ...)`) if behind a reverse proxy that handles HTTPS termination.
