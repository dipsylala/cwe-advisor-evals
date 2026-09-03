## Verdict

**Confirmed vulnerable.** The `DeleteAccount` action at line 32 performs a state-changing operation (account deletion) via a GET request without CSRF token validation. GET requests bypass CSRF middleware entirely, allowing attackers to force authenticated users to delete their accounts by embedding a malicious image or iframe tag on an attacker-controlled site.

## Source

The vulnerability originates in the route definition `[HttpGet("delete")]` and the unvalidated `confirmed` parameter passed from the query string to a state-changing sink.

## Fix

Change the HTTP verb from GET to POST and add CSRF token validation:

```csharp
// Before (vulnerable):
[HttpGet("delete")]
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

// After (fixed):
[HttpPost("delete")]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteAccount()
{
    var userId = _userContext.CurrentUserId;
    await _accountService.DeleteAccountAsync(userId);

    return RedirectToAction("SignedOut", "Home");
}
```

The `ConfirmDelete` view must be updated to submit a form via POST with the anti-forgery token instead of linking directly to the delete endpoint:

```csharp
// In ConfirmDelete.cshtml (view, not controller):
<form method="post" action="@Url.Action("DeleteAccount", "Account")">
    @Html.AntiForgeryToken()
    <p>Are you sure you want to delete your account?</p>
    <button type="submit">Yes, delete my account</button>
</form>
```

## Explanation

CSRF middleware in ASP.NET Core only validates POST, PUT, DELETE, and PATCH requests. GET requests bypass the middleware entirely, even when global anti-forgery protection is enabled. This means any GET endpoint that modifies state is unprotected—an attacker can trigger it by embedding `<img src="https://example.com/account/delete?confirmed=true">` on a malicious page, and browsers will automatically send the victim's session cookie.

The fix moves the state-changing operation to POST, where the `[ValidateAntiForgeryToken]` attribute (or global `AutoValidateAntiforgeryTokenAttribute`) will enforce a valid anti-forgery token. The existing confirmation page now serves as a safe intermediary: it renders the warning and the POST form with the token, preventing CSRF while preserving the user confirmation step.

The `confirmed` parameter is removed because the confirmation is now enforced by the user submitting the form from the confirmation page itself, not by a query string parameter that can be forged.

## Behaviour changes

- **Before:** Visiting `GET /account/delete?confirmed=true` directly deletes the account. A malicious page can force this via an embedded resource.
- **After:** The `/account/delete` endpoint only accepts POST requests. Visiting `GET /account/delete` returns a 405 Method Not Allowed. The only way to delete an account is to submit the form from the confirmation page with a valid anti-forgery token, which proves the request originated from the application itself and was not forged.
- **User-facing change:** The delete link becomes a button on the confirmation page instead of a direct link, requiring one additional click via form submission.
