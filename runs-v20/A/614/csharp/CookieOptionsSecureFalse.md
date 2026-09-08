## Verdict

Confirmed. The `CookieOptions` instance used for `Response.Cookies.Append("AuthToken", authToken, options)` does not set `Secure`, so it defaults to `false`. `CookieOptions.Secure` controls whether ASP.NET Core marks the outgoing `Set-Cookie` header with the `Secure` attribute; left at its default, the browser will also send `AuthToken` back over a plain HTTP connection to the same host. Since this cookie carries an authentication token (`authToken`), any network position that can observe or downgrade a request to HTTP can capture it.

## Source

`authToken`, taken directly from the query string via `[FromQuery] string authToken` in `RememberMe`, is written unmodified into the `AuthToken` cookie value.

## Fix

### File: CookieOptionsSecureFalse.cs

```csharp
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("account")]
    public class AccountController : ControllerBase
    {
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
    }
}
```

## Explanation

The only change needed at the sink is adding `Secure = true` to the `CookieOptions` object before it reaches `Response.Cookies.Append`. `CookieOptions.Secure` defaults to `false` in ASP.NET Core, so unless a set of global cookie policy options (`CookiePolicyOptions.Secure = CookieSecurePolicy.Always`, applied via `app.UseCookiePolicy()`) is configured elsewhere in the pipeline to override it, this cookie is otherwise sent over both HTTP and HTTPS. Setting `Secure = true` explicitly at the point the cookie is created removes the dependency on that global configuration existing (or being applied to this cookie) and makes the browser withhold `AuthToken` from any non-TLS request, closing the plaintext-interception path for this long-lived (30-day) authentication token.

`SameSite = SameSiteMode.Strict` is added as defense-in-depth: this is a persistent authentication cookie (`HttpOnly` and a 30-day expiry already show the intent), and restricting it to same-site requests reduces exposure to cross-site request forgery and cross-site leakage. It is not itself a fix for the reported finding and does not substitute for `Secure`.

`HttpOnly` was already correctly set and is left unchanged. No other secondary properties (`Path`, `Domain`) are added since the original code did not set them and the finding is specific to the missing `Secure` attribute.
