## Verdict

exploitable

## Source

`authToken` - the `[FromQuery] string authToken` parameter of `AccountController.RememberMe(string authToken)`, taken directly from the request query string with no validation or transformation.

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
                Expires = DateTimeOffset.UtcNow.AddDays(30)
            };

            Response.Cookies.Append("AuthToken", authToken, options);

            return Ok();
        }
    }
}
```

## Explanation

`Response.Cookies.Append("AuthToken", authToken, options)` is the sink: it writes the attacker-influenced `authToken` value into a persistent (30-day) authentication cookie using the `CookieOptions` instance built two lines above. That instance set `HttpOnly = true` and `Expires` but left `Secure` unset, so it defaults to `false` and the browser will happily send this cookie over a plaintext HTTP connection, letting a network attacker capture the long-lived auth token via interception (e.g. on shared Wi-Fi or through a downgrade/mixed-content request) even if the site is primarily served over HTTPS. The fix adds `Secure = true` to the same `CookieOptions` object, which is the concrete remediation the C# guidance for CWE-614 prescribes (`Set Secure = true on every CookieOptions used with Response.Cookies.Append()`). With `Secure = true`, the browser will only transmit `AuthToken` over an HTTPS connection, closing the interception path while leaving every other property of the cookie (name, value, `HttpOnly`, `Expires`) unchanged.

## Behaviour changes

- Added `Secure = true` to the `CookieOptions` initializer. This is the sole change; it makes the browser withhold the `AuthToken` cookie on any plaintext HTTP request. This is the intended effect of the fix (it requires the site to be served over HTTPS for the "remember me" flow to keep working) and is not a side effect - it directly closes the CWE-614 finding.
- No other arguments, return values, control flow, or cookie attributes (`HttpOnly`, `Expires`, cookie name/value) were altered.

## Verification

Compiled the fixed file with the .NET SDK (`dotnet build`, .NET 10 / `net10.0`) inside a scratch ASP.NET Core "empty" project referencing `Microsoft.AspNetCore.Mvc` (the shared framework, no external NuGet packages needed), replacing only the entry-point `Program.cs` with a minimal `WebApplication.CreateBuilder(args).Build()` so the project had a valid entry point alongside the controller. Build succeeded: 0 warnings, 0 errors. The only API used beyond the original code is the `CookieOptions.Secure` property, which is part of `Microsoft.AspNetCore.Http.CookieOptions` (already in scope via the existing `Microsoft.AspNetCore.Mvc` usings) and is named explicitly in the loaded csharp guidance's Key Principles and Remediation Steps.

## Assumptions

None - the fix directly follows the taint sink and remediation step named in `cwe/614/csharp/INDEX.md` (`Response.Cookies.Append()` with `Secure` unset -> add `Secure = true` to the `CookieOptions`). `SameSite = SameSiteMode.Strict` and app-wide `CookiePolicyOptions`/HSTS hardening from the guidance's Key Principles were intentionally not added here: they are defence-in-depth/global-configuration recommendations outside this single-file finding's call chain, and adding a `SameSite` restriction would be a behaviour change not required to close this specific CWE-614 finding.
