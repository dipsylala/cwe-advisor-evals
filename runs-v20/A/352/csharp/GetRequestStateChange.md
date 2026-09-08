## Verdict

Confirmed. `DeleteAccount` performs a state change (permanent account deletion) but is bound to `[HttpGet("delete")]`. A GET endpoint receives no CSRF protection in ASP.NET Core: `[ValidateAntiForgeryToken]` / the framework's antiforgery machinery is only ever emitted into and checked against unsafe-verb requests (POST/PUT/PATCH/DELETE), and browsers attach session cookies automatically to any cross-site GET, including one triggered by a plain link, an `<img>` tag, or a `<iframe>` an attacker controls. A logged-in user who merely loads a page containing `<img src="https://storefront.example/account/delete?confirmed=true">` has their account deleted with no interaction and no way to detect it in advance.

## Source

The forged request's trigger is any cross-origin content the victim's browser renders while authenticated to the site - an attacker-controlled page containing an auto-loading tag or link targeting `GET /account/delete?confirmed=true`. The browser attaches the ASP.NET Core session/auth cookie automatically because the request is same-origin from the cookie's point of view (it targets the storefront's own origin), even though it originates from a different site. Sink is the state-changing call at line 41 of the original file (`_accountService.DeleteAccountAsync(userId)`), reached solely because the action accepts GET with no origin or token check.

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

        // Called from the confirmation page's form submission. The action now only accepts
        // POST, and ValidateAntiForgeryToken requires the per-session token that ASP.NET
        // Core's antiforgery middleware issues to the confirmation form and validates here -
        // a cross-site request has no way to read or supply that token, so an attacker-hosted
        // <img>/<iframe>/auto-submitting form can no longer trigger the deletion.
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

Two changes close the finding: the route attribute moves from `[HttpGet("delete")]` to `[HttpPost("delete")]`, and `[ValidateAntiForgeryToken]` is added. Moving to POST alone is not sufficient - a cross-site `<form>` can still auto-submit a POST - so the antiforgery attribute is the load-bearing part of the fix; it rejects any request that does not carry the anti-forgery token ASP.NET Core's `IAntiforgery` service issues per authenticated session, and that token is never exposed to a third-party origin (it is neither in a URL nor readable by cross-origin script under the same-origin policy, and a forged form cannot obtain a valid copy).

This does require the confirmation view (`ConfirmDelete.cshtml`, outside this file) to render an HTML `<form method="post" asp-action="DeleteAccount">` in place of the current link, with the token included automatically by the `asp-action` tag helper (or explicitly via `@Html.AntiForgeryToken()` if the form is built without tag helpers), and the hidden `confirmed` value posted as a form field. That view file is not part of this change set, but the controller signature (`POST`, form-bound `bool confirmed`) is compatible with a standard MVC form post and requires no further controller changes once the view is updated.

No unrelated behavior changes: the confirmation GET at `delete/confirm` is untouched, and the redirect-to-confirmation fallback when `confirmed` is false is preserved.
