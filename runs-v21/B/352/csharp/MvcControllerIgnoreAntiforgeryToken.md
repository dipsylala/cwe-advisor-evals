## Verdict

exploitable

## Source

POST request to the UpdateSettings action from an unauthenticated attacker's website, carrying the victim's session cookie (which the browser attaches automatically).

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
    // filter while a legacy AJAX client was migrated. The migration finished and the
    // [IgnoreAntiforgeryToken] attribute has been removed to re-enable CSRF protection.
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

The UpdateSettings action is a POST endpoint that modifies state (updates the user's email address) while the user is authenticated. The original code explicitly disabled CSRF protection with the `[IgnoreAntiforgeryToken]` attribute, creating a vulnerability where an attacker could craft a forged POST request that the user's browser would execute using their active session cookie.

The fix removes the `[IgnoreAntiforgeryToken]` attribute, allowing the application's built-in anti-forgery protection (the global `AutoValidateAntiforgeryTokenAttribute` filter mentioned in the comments) to validate that each request includes a server-issued CSRF token. The framework compares this token against the one stored in the user's session before processing the state-changing operation, ensuring the request originated from the application itself and not from an attacker-controlled site.

The comment has been updated to reflect that the temporary workaround has been removed now that the legacy AJAX client migration is complete.

## Behaviour changes

None. The application's forms (which use `@Html.AntiForgeryToken()` or auto-generated Tag Helpers) already include valid anti-forgery tokens in their requests, so existing functionality is preserved. Requests without valid tokens (forged requests from other sites) are now correctly rejected by the framework's validation middleware.
