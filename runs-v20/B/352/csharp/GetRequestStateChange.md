## Verdict

Confirmed. `DeleteAccount` is a state-changing action (permanently deletes the authenticated user's account) reachable by a plain `GET` request. CSRF protection - whether the framework-default filter, a global `AutoValidateAntiforgeryTokenAttribute`, or a per-action `[ValidateAntiForgeryToken]` - only ever validates non-safe HTTP methods. A `GET` route bypasses that check entirely regardless of how CSRF is configured elsewhere in the application, so an attacker page containing `<img src="https://storefront.example/account/delete?confirmed=true">` (or an auto-navigating link/iframe) causes the victim's browser to attach their session cookie and execute the deletion with no user interaction and no origin check.

## Source

Attacker-controlled cross-site request (forged navigation/`<img>`/`<iframe>` load), carrying the victim's ambient session cookie via `[Authorize]`. No token, header, or origin check gates the request.

## Fix

The route is `GET` because it is the target of a link on the confirmation page (`ConfirmDelete`), not because it needs to be safely retryable or bookmarkable - it mutates state. Per the CSRF remediation guidance, the correct fix is to move the mutating action to `POST` (not to bolt a token onto a `GET`), while keeping `ConfirmDelete` as the `GET` entry point that renders the confirmation page. `DeleteAccount` becomes a `POST` action guarded by `[ValidateAntiForgeryToken]`; ASP.NET Core's MVC service registration (`AddControllersWithViews`/`AddMvc`/`AddRazorPages`) already wires up the antiforgery services by default, so no `Startup`/`Program.cs` change is required for this attribute to work.

This also means the confirmation page's "Yes, delete my account" control must become a `<form method="post">` (with the antiforgery token supplied automatically by MVC's form tag helper, or explicit `@Html.AntiForgeryToken()`) posting to `/account/delete`, rather than a plain link - see Behaviour changes. That view template is not part of the provided call chain, so its file is not included below, but the controller-side contract it must now satisfy is documented in the code comment.

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
        // The confirmation view's "Yes, delete my account" control must be a <form method="post">
        // (with the antiforgery token, e.g. via a Tag Helper or @Html.AntiForgeryToken()) posting
        // to this action, not a plain link - a GET link can no longer trigger the delete.
        [HttpGet("delete/confirm")]
        public IActionResult ConfirmDelete()
        {
            return View();
        }

        // Moved from [HttpGet] to [HttpPost] with [ValidateAntiForgeryToken]: CSRF filters only ever
        // validate non-safe methods, so the previous GET route bypassed anti-forgery checks entirely
        // regardless of configuration. A cross-site <img>/<iframe> or auto-loading link can no longer
        // reach this action, and any form/AJAX call now needs a valid same-origin
        // __RequestVerificationToken.
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

The only change to the sink is `[HttpGet("delete")]` -> `[HttpPost("delete")]` plus `[ValidateAntiForgeryToken]`. Everything downstream of the route/method attributes - the `confirmed` check, the `_userContext.CurrentUserId` lookup, the call to `_accountService.DeleteAccountAsync`, and both redirects - is unchanged, so the sink's existing contract (return value, redirect targets, failure behaviour on an unconfirmed request) is fully preserved. `[ValidateAntiForgeryToken]` and `[HttpPost]` both come from `Microsoft.AspNetCore.Mvc`, which the file already imports, so no new `using` was needed. `confirmed` still binds via MVC's default value provider, which covers form fields on a `POST` the same way it covered the query string on the prior `GET`, so no parameter-binding attribute was added.

This closes the weakness because CSRF validation - whichever mechanism the application uses (global auto-validation, a per-controller filter, or this explicit attribute) - only inspects non-safe HTTP methods. As a `GET`, the endpoint was structurally unreachable by any CSRF check; as a `POST` with `[ValidateAntiForgeryToken]`, every request must now carry a valid `__RequestVerificationToken` bound to the authenticated user's antiforgery cookie, which a cross-site page cannot forge or read due to the same-origin policy.

**Check performed:** the fixed file was copied into a scratch ASP.NET Core (`net8.0`/`Microsoft.NET.Sdk.Web`) project alongside stub `IAccountService`/`IUserContext` interfaces matching the members the controller calls, and built with `dotnet build`. Build succeeded with 0 warnings and 0 errors, confirming `[HttpPost]` and `[ValidateAntiForgeryToken]` resolve correctly from the existing `Microsoft.AspNetCore.Mvc` import and the method signature is otherwise unchanged.

## Behaviour changes

- `DeleteAccount` no longer accepts `GET`. Any existing plain link, bookmark, browser history entry, or auto-loading resource pointed at `GET /account/delete?confirmed=true` now gets a `405 Method Not Allowed` instead of deleting the account.
- The confirmation page's "Yes, delete my account" control must be changed from a link to a `POST` form (carrying the antiforgery token) targeting `/account/delete`; this is required for the legitimate flow to keep working, but the view template lives outside the provided file and is not part of this fix.
- Requests to `POST /account/delete` now require a valid `__RequestVerificationToken` (cookie plus matching hidden field or header); a request without one - including a same-origin AJAX call that doesn't attach it - now receives `400 Bad Request` instead of proceeding.
