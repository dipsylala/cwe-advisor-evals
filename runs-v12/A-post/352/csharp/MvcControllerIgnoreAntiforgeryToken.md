## Verdict
Remove the `[IgnoreAntiforgeryToken]` attribute from the `UpdateSettings` action. The attribute disables CSRF protection and was added as a temporary workaround during legacy client migration, which has since completed.

## Source
Line 47 in AccountController.cs declares `[IgnoreAntiforgeryToken]` on the `UpdateSettings` POST handler. The comment (lines 41–44) explicitly documents that this attribute was added during migration of a legacy AJAX client, but the migration is finished and the attribute was never removed. Without CSRF protection, an attacker can forge a POST request to change the authenticated user's email by embedding a request in a malicious webpage visited by that user.

## Fix
Delete the `[IgnoreAntiforgeryToken]` attribute from line 47. The ASP.NET Core `AutoValidateAntiforgeryTokenAttribute` filter (enabled at the app level per the comment) will automatically validate the antiforgery token on POST requests. For form submissions, include a hidden input with the token; for AJAX requests, pass the token in a request header. ASP.NET Core provides helpers to inject the token into forms and to retrieve it from cookies for client-side use.

```csharp
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
```

## Explanation
The `[IgnoreAntiforgeryToken]` attribute is a security-critical bypass of CSRF protection. State-changing operations like updating email must validate that the request originated from the legitimate user's browser, not from an attacker's site. The app's `AutoValidateAntiforgeryTokenAttribute` provides this protection automatically on POST, PUT, PATCH, and DELETE requests. Removing the bypass re-enables validation. The legacy AJAX migration that prompted the temporary bypass is complete, so the exemption is no longer needed.
