## Verdict

Exploitable. The authentication token cookie is created without `Secure = true`, allowing it to be transmitted over unencrypted HTTP connections.

## Source

The `authToken` parameter is extracted from the HTTP query string at line 10 (`[FromQuery] string authToken`), making it attacker-controlled via HTTP request manipulation.

## Fix

**Vulnerable code:**
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

The `CookieOptions` object is missing the `Secure = true` property, which means the authentication cookie will be transmitted over both HTTP and HTTPS connections. An attacker intercepting HTTP traffic can capture the plaintext authentication token. Setting `Secure = true` enforces transmission only over HTTPS, preventing interception over unencrypted connections. This is a mandatory requirement for any cookie carrying session or authentication data.

## Behaviour changes

The fix adds `Secure = true` to the cookie options. The cookie will now only be transmitted over HTTPS connections; any attempt to send it over HTTP will be blocked by the browser. This is the intended security behavior and prevents the downgrade attack that exploits the absence of the flag. No other contract changes occur—the cookie still has `HttpOnly = true`, expires in 30 days, and carries the same authentication token value.
