## Verdict

Confirmed. `UpdateSettings` is a state-changing POST action that carries `[IgnoreAntiforgeryToken]`, which opts it out of the app-wide `AutoValidateAntiforgeryTokenAttribute` filter. Because the controller is only `[Authorize]`, the browser will attach the authentication cookie automatically on a cross-site POST, and with antiforgery validation disabled the server has no way to tell a forged request (submitted from an attacker-controlled page) from a legitimate one. Any authenticated user who visits a malicious page while logged in can have their account email silently changed.

## Source

The tainted/attacker-triggered element here is not request data but the cross-site request itself: an attacker's page can submit a form (or fetch with `credentials: 'include'`) to `POST /Account/UpdateSettings`. The browser attaches the victim's session cookie automatically, so the request arrives authenticated even though the victim never intended to submit it.

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

The `[IgnoreAntiforgeryToken]` attribute was the sink: it disabled the app's global `AutoValidateAntiforgeryTokenAttribute` filter for this single action, so `UpdateSettings` accepted POSTs with no antiforgery token check at all. The fix removes that attribute so the endpoint falls back to the app-wide filter, which requires a valid antiforgery token on every unsafe HTTP verb.

For this to work end to end, the `Settings` view's form must use ASP.NET Core's built-in form tag helper (`<form asp-action="UpdateSettings" method="post">`) or otherwise emit `@Html.AntiForgeryToken()`, so the hidden `__RequestVerificationToken` field is present and matches the cookie the filter checks against; that is unchanged by this fix since the view is not part of this file. No allowlist, extra header check, or custom origin validation is layered on top - the antiforgery token pair (cookie + form field, unguessable per-session) is the correct primary defense here and doing more would be redundant. Removing the attribute is not a behavioral regression: the code comment confirms the legacy AJAX client that needed the opt-out has already been migrated, so no caller still depends on the unauthenticated-token path.

To verify: a POST to `/Account/UpdateSettings` with a valid session cookie but no `__RequestVerificationToken` (or a mismatched one) should now return 400, whereas the same request with a valid token/cookie pair should still succeed and update the email - confirming the check is both present and not simply always-failing.
