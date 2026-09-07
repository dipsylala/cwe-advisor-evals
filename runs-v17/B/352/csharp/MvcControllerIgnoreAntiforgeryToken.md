## Verdict
exploitable

## Source
Attacker-controlled cross-site request (originating from a malicious website).

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

    // The app-wide AutoValidateAntiforgeryTokenAttribute filter now validates
    // this endpoint, protecting it from CSRF attacks.
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
The vulnerability was introduced by the `[IgnoreAntiforgeryToken]` attribute on line 47, which explicitly disables ASP.NET Core's automatic CSRF protection for this endpoint. The attribute was applied during a legacy AJAX client migration but was never removed once the migration completed. 

Removing the `[IgnoreAntiforgeryToken]` attribute re-enables the app-wide `AutoValidateAntiforgeryTokenAttribute` global filter, which now validates that all POST requests to this endpoint include a valid server-controlled antiforgery token. This prevents attackers from forging requests that change the authenticated user's email address. The framework's token validation compares the request token against the user's session-bound token using constant-time comparison, closing the CSRF attack vector.

## Behaviour changes
none

The fix removes only the disabling attribute. The method signature, return types, error handling, and control flow remain unchanged. The sink contract is preserved: the action still returns `BadRequest()` on validation failure and `RedirectToAction()` on success. The only runtime difference is that requests without a valid antiforgery token now return a validation error (HTTP 400) instead of being processed.
