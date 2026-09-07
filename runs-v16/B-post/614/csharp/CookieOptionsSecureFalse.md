## Verdict

VULNERABLE. The authentication token cookie is set without the `Secure` flag, permitting transmission over unencrypted HTTP connections and exposing it to network interception.

## Source

Parameter `authToken` from `[FromQuery]` at the method signature (untrusted, attacker-controlled).

## Fix

Add `Secure = true` to the `CookieOptions` object before passing it to `Response.Cookies.Append()`.

Vulnerable code (line 12-19):
```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

Response.Cookies.Append("AuthToken", authToken, options);
```

Fixed code:
```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

Response.Cookies.Append("AuthToken", authToken, options);
```

## Explanation

The `CookieOptions.Secure` property defaults to `false`, which allows the browser to transmit the cookie over both HTTP and HTTPS. Setting `Secure = true` restricts transmission to HTTPS only, preventing interception over plaintext connections. This fix ensures the authentication token is protected by transport encryption as required by CWE-614 remediation guidance.

The fix preserves all existing behaviour: `HttpOnly = true` prevents JavaScript access, and the 30-day expiration is unchanged.

## Behaviour changes

- Cookies are now sent only over HTTPS connections; HTTP requests will not include this cookie.
- Requires HTTPS to be enforced site-wide; if the application serves HTTP traffic, clients will lose the authentication cookie and fail to authenticate.
