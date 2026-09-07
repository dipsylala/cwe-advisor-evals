## Verdict
Exploitable

## Source
The `authToken` parameter at line 10, sourced from `[FromQuery] string authToken` - attacker-controlled input from the query string.

## Fix
**Vulnerable code (line 12-19):**
```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

Response.Cookies.Append("AuthToken", authToken, options);
```

**Fixed code:**
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
The CookieOptions object was missing the `Secure = true` attribute. Without it, the authentication token cookie can be transmitted over unencrypted HTTP connections, exposing it to network interception. Adding `Secure = true` restricts the cookie to HTTPS-only transmission, enforcing transport-layer encryption and closing the weakness. The `HttpOnly` flag prevents client-side script access, providing defence-in-depth alongside the fix.

## Behaviour changes
The cookie will now only be transmitted over HTTPS connections. An application running over HTTP will not send the cookie, which is the intended behaviour - this prevents leaking the authentication token on unencrypted connections. If the application does not enforce HTTPS site-wide, this change will break authentication flows over HTTP, making the security misconfiguration visible immediately rather than silently issuing insecure cookies.
