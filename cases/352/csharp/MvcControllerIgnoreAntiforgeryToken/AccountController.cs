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
    // filter while a legacy AJAX client was migrated. The migration finished but the
    // attribute was never removed, so the endpoint now accepts forged POSTs from any
    // origin as long as the session cookie rides along.
    [HttpPost]
    // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    [IgnoreAntiforgeryToken]
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
