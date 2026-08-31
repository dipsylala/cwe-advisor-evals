## Verdict
Confirmed CWE-614. The cookie options explicitly omit `Secure = true`, allowing the authentication token to be transmitted over unencrypted HTTP connections in a downgrade attack scenario.

## Source
Line 19: `Response.Cookies.Append("AuthToken", authToken, options);`

The sink is the `Append()` call with `CookieOptions options` that lacks the `Secure` flag.

## Fix
Add `Secure = true` to the CookieOptions object:

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};
```

## Explanation
The `Secure` attribute on `CookieOptions` instructs the browser to transmit the cookie only over HTTPS connections. Without this flag, the browser will send the authentication token over unencrypted HTTP if the user visits an HTTP variant of the site or follows a downgrade redirect, exposing it to network interception. Setting `Secure = true` is the primary defence against session fixation and credential theft over unencrypted channels.
