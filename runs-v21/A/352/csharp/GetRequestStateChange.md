## Verdict
CONFIRMED. The `DeleteAccount` action performs a state-changing operation (account deletion) on an HTTP GET request without CSRF protection. Attackers can trick authenticated users into triggering account deletion via malicious links or embedded requests.

## Source
The vulnerability exists in the `DeleteAccount` method (line 32) which uses `[HttpGet]` to handle account deletion. State-changing operations must use POST with anti-forgery token validation to prevent cross-site request forgery attacks.

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

        // Called from the confirmation page's "Yes, delete my account" form.
        // Changed from GET to POST and added ValidateAntiForgeryToken to prevent CSRF attacks.
        // State-changing operations must use POST with anti-forgery token validation.
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
The fix requires two changes to the AccountController.cs file:

1. **Change HTTP method from GET to POST** (line 32): Replace `[HttpGet("delete")]` with `[HttpPost("delete")]`. State-changing operations must never use GET, which allows automatic cookie submission via cross-site navigation, image tags, iframes, or link prefetching.

2. **Add CSRF token validation** (line 33): Add the `[ValidateAntiForgeryToken]` attribute. ASP.NET Core's anti-forgery middleware validates that the request includes a matching anti-forgery token, which the confirmation form must submit as a hidden field. This ensures the request originates from the same site.

The corresponding confirmation page (ConfirmDelete view) must be updated to use an HTML form with POST method and include `@Html.AntiForgeryToken()` to generate the CSRF token. This prevents attackers from triggering the deletion via cross-site requests even if an authenticated user visits a malicious page.

