## Verdict

CONFIRMED - Vulnerable code. The `CookieOptions` object lacks `Secure = true`, allowing the authentication cookie to be transmitted over plaintext HTTP.

## Source

`authToken` parameter from `[FromQuery] string authToken` (line 10) - attacker-controlled input supplied from HTTP query parameters.

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

Added `Secure = true` to the `CookieOptions` object. This flag instructs the browser to only transmit the cookie over HTTPS connections, preventing the authentication token from being intercepted over plaintext HTTP. The `Secure` attribute is mandatory for any cookie containing sensitive session or authentication data. Combined with the already-present `HttpOnly = true`, this prevents both network interception and client-side JavaScript access to the cookie, providing defence-in-depth protection.

## Behaviour changes

- The cookie will now be rejected by the browser if transmitted over HTTP, and only sent over HTTPS connections.
- Clients attempting to reach the application over plain HTTP will not receive the `AuthToken` cookie in the response; the server continues to issue it, but the browser enforces the `Secure` restriction.
- In development environments that use HTTP instead of HTTPS, the `Secure` flag will prevent the cookie from being set. To test locally over HTTP, temporarily remove `Secure = true` during development, then restore it before deployment.
