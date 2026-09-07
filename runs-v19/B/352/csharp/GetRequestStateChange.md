## Verdict

exploitable

## Source

The vulnerable GET request at line 32 (`[HttpGet("delete")]`) receives an implicit `confirmed` boolean parameter from the query string, which is attacker-controlled via a crafted URL. The parameter flows directly to the account deletion logic without CSRF protection.

## Fix

### File: AccountController.cs

```csharp
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Storefront.Controllers
{
    [Authorize]
    [Route("account")]
    public class AccountController : Controller
    {
        private readonly IAccountService _accountService;
        private readonly IUserContext _userContext;

        public AccountController(IAccountService accountService, IUserContext userContext)
        {
            _accountService = accountService;
            _userContext = userContext;
        }

        // Confirmation step: renders a page asking the user to type "DELETE" before continuing.
        [HttpGet("delete/confirm")]
        public IActionResult ConfirmDelete()
        {
            return View();
        }

        // State-changing endpoint for account deletion.
        // Changed from GET to POST to enable CSRF protection via [ValidateAntiForgeryToken].
        // The confirmation page's form will POST to this endpoint with an anti-forgery token.
        [HttpPost("delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAccount(bool confirmed)
        {
            if (!confirmed)
            {
                return RedirectToAction(nameof(ConfirmDelete));
            }

            var userId = _userContext.CurrentUserId;
            await _accountService.DeleteAccountAsync(userId);

            return RedirectToAction("SignedOut", "Home");
        }
    }
}
```

## Explanation

The vulnerability existed because state-changing operations must not be exposed on GET endpoints. GET requests are idempotent by design and browsers automatically attach cookies to them, making them vulnerable to CSRF attacks via malicious links, images, or iframes that an attacker controls. ASP.NET Core's CSRF middleware validates only POST, PUT, and DELETE requests—GET routes bypass protection entirely. The fix moves the deletion logic from `[HttpGet("delete")]` to `[HttpPost("delete")]` and adds the `[ValidateAntiForgeryToken]` attribute, which ensures ASP.NET Core validates an anti-forgery token on every deletion request. The confirmation page (rendered by the GET endpoint) now submits a form via POST with the token, completing the two-step confirmation while defending against cross-site forgery. The `[Authorize]` attribute continues to enforce user authentication, and the confirmation flag remains part of the server-side validation chain.

## Behaviour changes

1. **HTTP method changed from GET to POST**: The endpoint is no longer reachable via hyperlinks or automatic browser navigation; state changes now require an explicit form submission. This is the core of the fix and reflects the security requirement that state-changing operations use unsafe methods.

2. **Request format changed**: The `confirmed` parameter now travels in the POST body (form data) or query string via model binding, rather than exclusively in the query string. ASP.NET Core's default model binder accepts both, so existing confirmation logic remains functional.

3. **Added anti-forgery token requirement**: The `[ValidateAntiForgeryToken]` attribute requires a server-validated token in the request. If the application has configured `services.AddAntiforgery()` in Startup.cs and the confirmation view includes `@Html.AntiForgeryToken()`, the token is automatically validated. Without these prerequisites, the attribute will reject all requests until they are in place.

4. **Confirmation page remains accessible via GET**: The GET endpoint at `/account/delete/confirm` is unchanged and continues to render the confirmation form. The form's action now targets POST `/account/delete` instead of GET `/account/delete`, changing the user experience from a link-based flow to a form-based flow.

No other contract changes: the action still returns `IActionResult` redirects, respects the `[Authorize]` attribute, and uses the same `_accountService` and `_userContext` dependencies.
