## Verdict

Exploitable. The `AuthToken` cookie carries authentication data and is set without the `Secure` flag, allowing it to be transmitted over unencrypted HTTP connections.

## Source

`authToken` parameter from query string (`[FromQuery] string authToken`) at line 10.

## Fix

**Vulnerable code (line 12-16):**
```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};
```

**Fixed code:**
```csharp
var options = new CookieOptions
{
    Secure = true,
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};
```

## Explanation

The fix adds `Secure = true` to the `CookieOptions` object. This enforces that the cookie is only transmitted over HTTPS connections, preventing the `AuthToken` (which carries authentication credentials) from being exposed over plaintext HTTP. The `Secure` flag is required for any sensitive cookie; without it, an attacker who can intercept unencrypted traffic can capture the authentication token.

## Behaviour changes

None. Adding `Secure = true` to `CookieOptions` does not change the API contract or affect any other aspect of cookie handling. The cookie will continue to function identically over HTTPS (which should already be enforced site-wide). Over HTTP, the flag simply prevents the cookie from being transmitted at all, which is the correct and intended behaviour for sensitive cookies.
