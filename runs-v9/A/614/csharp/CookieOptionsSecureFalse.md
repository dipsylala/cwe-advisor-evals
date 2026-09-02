## Verdict

Confirmed. The `CookieOptions` used to set the `AuthToken` cookie does not set `Secure = true`, so the browser will send this authentication cookie over plain HTTP as well as HTTPS, exposing it to interception on an unencrypted connection.

## Source

`E:/Github/cwe-advisor/evals/cases/614/csharp/CookieOptionsSecureFalse/CookieOptionsSecureFalse.cs`, lines 12-19:

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

Response.Cookies.Append("AuthToken", authToken, options);
```

`authToken` is a query-string value carried straight into a long-lived (`AddDays(30)`) authentication cookie. `CookieOptions.Secure` defaults to `false`, so ASP.NET Core does not add the `Secure` attribute unless it is set explicitly, and the resulting `Set-Cookie` header omits it.

## Fix

```csharp
[HttpPost("remember-me")]
public IActionResult RememberMe([FromQuery] string authToken)
{
    var options = new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Expires = DateTimeOffset.UtcNow.AddDays(30)
    };

    // SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
    Response.Cookies.Append("AuthToken", authToken, options);

    return Ok();
}
```

Also confirm the site enforces HTTPS end-to-end (e.g. `app.UseHttpsRedirection()` and HSTS via `app.UseHsts()` in `Program.cs`/`Startup.cs`), since `Secure` only prevents the cookie from being sent over an insecure connection - it does not force the connection itself to be secure.

## Explanation

Setting `Secure = true` instructs the browser to attach the `AuthToken` cookie only when the request is made over HTTPS, so it can never be sent in cleartext where a network-level attacker (e.g. on a shared Wi-Fi network, or via SSL-stripping) could capture it and hijack the "remember me" session. `HttpOnly` was already present, which blocks script-based (XSS) access to the cookie, but that is a distinct protection from transport confidentiality - both are needed for a long-lived authentication token.

`SameSite = SameSiteMode.Strict` is added defense-in-depth: it stops the cookie from being attached to cross-site requests, reducing CSRF exposure for the same authentication token; it is not required to close the reported `Secure`-attribute finding but is a low-cost improvement given the cookie's sensitivity and 30-day lifetime.

After the fix, verify by inspecting the `Set-Cookie` response header for `AuthToken` (in browser dev tools or via `curl -i`) and confirming it includes `Secure`; also confirm the cookie is not sent when the same endpoint is reached over plain HTTP (it should be dropped by the browser, or the request should be redirected to HTTPS first).
