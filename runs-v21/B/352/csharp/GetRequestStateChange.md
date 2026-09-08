## Verdict

The vulnerability is **confirmed and remediable**. The `DeleteAccount()` action is a state-changing operation accessible via GET, which bypasses CSRF middleware protection. CSRF tokens validate only non-safe HTTP methods (POST/PUT/DELETE); a GET endpoint that modifies state is never protected, even with a global `[ValidateAntiForgeryToken]` filter enabled.

## Source

The confirmation page `/account/delete/confirm` renders an interface where an authenticated user can request account deletion. The unsafe state change is triggered by a GET request to `/account/delete` (line 32).

## Fix

The account deletion action must be changed from GET to POST and protected with an anti-forgery token. The confirmation page's form will POST to the endpoint instead of using a link, ensuring the browser cannot be forced to submit by an attacker-controlled cross-site request.

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

        // Called from the confirmation page's form submission.
        // Now uses POST with anti-forgery token validation to prevent CSRF.
        [HttpPost("delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAccount()
        {
            var userId = _userContext.CurrentUserId;
            await _accountService.DeleteAccountAsync(userId);

            return RedirectToAction("SignedOut", "Home");
        }
    }
}
```

## Explanation

Changed the `DeleteAccount` endpoint from `[HttpGet("delete")]` to `[HttpPost("delete")]` and added `[ValidateAntiForgeryToken]` attribute. This forces the account deletion to be triggered only via a form submission containing a server-issued anti-forgery token, not via a simple GET request that browsers automatically follow.

Removed the `confirmed` query parameter because the intent is now conveyed by the form submission itself—if the user POSTs to this endpoint, they have confirmed the deletion from the confirmation page. The confirmation page's view must render a form with `@Html.AntiForgeryToken()` that POSTs to this endpoint.

The `[Authorize]` attribute at the controller level ensures only authenticated users can reach this endpoint; `[ValidateAntiForgeryToken]` ensures only requests from the application itself (carrying the server-issued token) are processed. Together, these prevent CSRF attacks.

## Behaviour changes

- Users must now submit a form (POST) rather than click a link (GET) to delete their account.
- The confirmation page view must include a POST form with an anti-forgery token (`@Html.AntiForgeryToken()`).
- Direct requests to `/account/delete` via GET (e.g. bookmarks, email links) will receive a 404 or 405 (Method Not Allowed) instead of processing the deletion. Users must navigate through the confirmation page to trigger deletion.
- The `confirmed` query parameter is no longer used; form-based submission is the only path to account deletion.
