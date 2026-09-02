## Verdict

CWE-614 confirmed. The cookie carrying the authentication token is set without the `Secure` attribute, permitting transmission over insecure HTTP connections when HTTPS is expected.

## Source

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

Response.Cookies.Append("AuthToken", authToken, options);
```

The `CookieOptions` object lacks `Secure = true`. Although `HttpOnly` is correctly set to prevent JavaScript access, the missing `Secure` flag allows the cookie to be sent over unencrypted HTTP, exposing the authentication token to network eavesdropping.

## Fix

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

Response.Cookies.Append("AuthToken", authToken, options);
```

Set `Secure = true` in the `CookieOptions` initialization. This ensures the cookie is transmitted only over HTTPS connections.

## Explanation

The `Secure` attribute is a browser-enforced flag that prevents cookies from being sent over unencrypted HTTP. Without it, an attacker on the network path can intercept the authentication token during transmission, even if the application design assumes HTTPS.

Setting `Secure = true` on the `CookieOptions` object enforces this protection at the application level. The browser will refuse to send the cookie over HTTP, limiting its exposure to HTTPS contexts only.

Since this cookie carries an authentication token (sensitive data), the `Secure` attribute is essential for defence-in-depth alongside the existing `HttpOnly = true`, which prevents JavaScript from accessing the token.
