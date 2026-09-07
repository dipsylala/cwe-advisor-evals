## Verdict
Confirmed. The `DeleteAccount` action uses `[HttpGet]` for a state-changing operation, violating CSRF defenses. GET requests are idempotent and lack built-in anti-forgery protections; browsers attach cookies automatically to any cross-origin GET request, allowing an attacker to trigger account deletion by crafting a malicious link or image tag.

## Source
The vulnerability is at line 32 in `AccountController.cs`. The `DeleteAccount` method is decorated with `[HttpGet("delete")]`, making it callable without explicit form submission or token validation. Since account deletion is a state-changing operation, the method should reject GET requests and require POST with an anti-forgery token.

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

        // Called from the confirmation page's "Yes, delete my account" form submission.
        // POST requests require explicit form submission and are protected by ASP.NET Core's
        // anti-forgery token validation by default, preventing CSRF attacks.
        [HttpPost("delete")]
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
The fix changes `[HttpGet("delete")]` to `[HttpPost("delete")]`. This is the primary defense for CWE-352 because:

1. **POST requires explicit form submission:** State-changing operations must use POST (or PUT/DELETE). A POST request cannot be triggered by a simple link, image tag, or redirect—it requires an explicit form submission with user interaction.

2. **Anti-forgery tokens are enforced by default:** ASP.NET Core applies the `[ValidateAntiForgeryToken]` attribute implicitly to POST requests on pages with forms, and the runtime validates tokens automatically in most middleware configurations. GET requests bypass this protection entirely.

3. **Browsers do not auto-submit forms across origins:** While browsers auto-attach cookies to GET requests, they block form submissions to cross-origin targets and require explicit credential handling for cross-origin POST requests, adding an additional CSRF barrier.

4. **Semantic correctness:** Deletion is a state-changing operation and must not be idempotent via GET. POST correctly signals that the action has side effects.

The confirmation flow remains in place (the form still checks the `confirmed` parameter), maintaining the existing user experience while closing the CSRF vector.
