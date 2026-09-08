## Verdict

Exploitable. CWE-352 (Cross-Site Request Forgery). Confidence: high.

## Source

- **Source**: an HTTP POST to `AccountController.UpdateSettings`, bound to `AccountSettingsRequest.NewEmail`. The action is `[Authorize]`-protected but relies solely on the ambient session cookie for authentication, and the `[IgnoreAntiforgeryToken]` attribute on line 47 opts this specific action out of the app-wide `AutoValidateAntiforgeryTokenAttribute` filter the surrounding comment says is registered globally. A browser will attach the victim's session cookie to a cross-site POST automatically, and with the antiforgery check disabled here, nothing else verifies the request originated from the application's own pages.
- **Sink**: `await _accountSettingsService.UpdateEmailAsync(userId, request.NewEmail);` at line 57 - a state-changing operation that persists a new contact email for the authenticated user's account, taken from `request.NewEmail` with no other authenticity check in between.
- **Path**: attacker-controlled page -> auto-submitted cross-site POST to `/Account/UpdateSettings` (session cookie riding along) -> `[IgnoreAntiforgeryToken]` skips the app-wide antiforgery filter -> `UpdateEmailAsync` runs, changing the account's email to an attacker-chosen value (a common precursor to full account takeover via password reset).

## Fix

### File: AccountController.cs

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ContosoApp.Controllers;

public interface IAccountSettingsService
{
    Task UpdateEmailAsync(string userId, string newEmail);
}

public class AccountSettingsService : IAccountSettingsService
{
    public Task UpdateEmailAsync(string userId, string newEmail)
    {
        // Persists the new contact email for the account.
        return Task.CompletedTask;
    }
}

public class AccountSettingsRequest
{
    public string NewEmail { get; set; } = string.Empty;
}

[Authorize]
public class AccountController : Controller
{
    private readonly IAccountSettingsService _accountSettingsService;

    public AccountController(IAccountSettingsService accountSettingsService)
    {
        _accountSettingsService = accountSettingsService;
    }

    [HttpGet]
    public IActionResult Settings()
    {
        return View();
    }

    // This action was opted out of the app-wide AutoValidateAntiforgeryTokenAttribute
    // filter while a legacy AJAX client was migrated. The migration is complete, so the
    // opt-out has been removed and the endpoint is validated by the app-wide filter again.
    [HttpPost]
    public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.NewEmail))
        {
            return BadRequest("Email is required.");
        }

        var userId = User.Identity?.Name ?? string.Empty;

        await _accountSettingsService.UpdateEmailAsync(userId, request.NewEmail);

        return RedirectToAction(nameof(Settings));
    }
}
```

## Explanation

The vulnerability was the `[IgnoreAntiforgeryToken]` attribute on `UpdateSettings`, which deliberately exempted this one action from the application's global `AutoValidateAntiforgeryTokenAttribute` filter - the source comment confirms the exemption was a temporary measure for a legacy AJAX client migration that has since finished. With the exemption in place, the action authenticated the caller only via the ambient session cookie, which a cross-site form submits automatically, so any page could force a logged-in user's browser to change their account email. The fix removes the `[IgnoreAntiforgeryToken]` attribute (and the now-stale part of the comment explaining it), which lets the pre-existing app-wide `AutoValidateAntiforgeryTokenAttribute` filter validate the `__RequestVerificationToken` on this POST again, exactly as it does for every other state-changing action in the application. No other line changed: the sink call, its arguments, and the method's return values are untouched, so the fix closes the CSRF gap without altering the endpoint's behavior for a legitimate, token-carrying request.

## Behaviour changes

- Removed `[IgnoreAntiforgeryToken]` and the sentence in the preceding comment that referenced the (now-finished) migration reason for it; no other attribute, parameter, argument, or return value was touched. This restores the same antiforgery enforcement every other action in the app already receives from the global filter - it is not a new mechanism, so `services.AddAntiforgery()` and the `AutoValidateAntiforgeryTokenAttribute` global filter registration are assumed to already exist in `Startup.cs`/`Program.cs` per the source comment ("app-wide ... filter"), which is outside this file and was not modified.
- Net effect for callers: any POST to `/Account/UpdateSettings` must now include a valid `__RequestVerificationToken` (form field or, for an AJAX/JSON caller, the `RequestVerificationToken` header) matching the user's antiforgery cookie, or the request is rejected with HTTP 400 before reaching the action body. The comment states the legacy AJAX client that needed the exemption has already been migrated, so no currently-supported caller should be sending token-less requests; if any caller still is, it was already relying on the same gap this fix closes and needs to add the token, not have it re-exempted.
- Verification: the fixed file was compiled with `dotnet build` (net8.0, `Microsoft.NET.Sdk.Web`, referencing `Microsoft.AspNetCore.Authorization` and `Microsoft.AspNetCore.Mvc`) in an isolated scratch project - build succeeded with 0 warnings and 0 errors. No new symbols, imports, or APIs were introduced by the fix (an attribute and part of a comment were deleted), so no additional name-existence check was needed.
