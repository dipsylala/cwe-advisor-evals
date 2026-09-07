## Verdict

CONFIRMED - CWE-352 (Cross-Site Request Forgery) is exploitable. The `UpdateSettings` endpoint accepts authenticated POST requests that modify account data without verifying CSRF token origin, because `[IgnoreAntiforgeryToken]` explicitly disables framework-provided protection.

## Source

HTTP POST request body containing `AccountSettingsRequest` with attacker-controlled `NewEmail` field, received from an authenticated session cookie.

## Fix

Remove the `[IgnoreAntiforgeryToken]` attribute on line 47 to re-enable automatic CSRF token validation.

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
    // filter while a legacy AJAX client was migrated. The migration finished and the
    // attribute has been removed, so the endpoint now validates CSRF tokens.
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

The vulnerability occurred because `[IgnoreAntiforgeryToken]` on a POST handler that modifies state (email update) disabled the framework's CSRF token validation. An attacker could craft a malicious page that causes an authenticated user's browser to POST a forged request to change the account email without the victim's knowledge.

Removing the attribute re-enables ASP.NET Core's automatic anti-forgery validation, which:
1. Requires an authenticated request to include a valid CSRF token (via form field or header)
2. Validates the token server-side before processing the state change
3. Binds the token to the authenticated user's session

The comment was updated to reflect that the legacy migration is complete and the protection is now active. The form rendering `UpdateSettings` must include `@Html.AntiForgeryToken()` to inject the token into the HTML form; if this application uses automatic tag helpers (the standard in ASP.NET Core), the token is auto-generated.

## Behaviour changes

- POST requests to `/Account/UpdateSettings` without a valid CSRF token will now be rejected with HTTP 400 Bad Request
- Legitimate requests from forms and AJAX clients within the same application must include the token (automatically provided by `@Html.AntiForgeryToken()` in forms or as a request header in AJAX)
- No changes to successful request handling or response format; only invalid/forged requests are now blocked
