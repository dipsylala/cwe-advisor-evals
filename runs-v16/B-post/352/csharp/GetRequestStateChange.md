## Verdict

Real vulnerability confirmed. The `DeleteAccount` action at line 32 handles a state-changing operation (account deletion) via HTTP GET, which bypasses CSRF middleware protection. Browsers automatically attach session cookies to cross-site requests, allowing an attacker to trick an authenticated user into deleting their account via a malicious link or embedded resource.

## Source

Authenticated user's session (via `HttpContext.User` claim binding to `_userContext.CurrentUserId`), attacked through automatic browser cookie transmission on any cross-site GET request to the endpoint.

## Fix

Change the account deletion from a GET action to a POST action with CSRF token validation:

```csharp
// Remove the vulnerable GET action (lines 32-44) and replace with:

[HttpPost("delete")]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteAccount()
{
    var userId = _userContext.CurrentUserId;
    await _accountService.DeleteAccountAsync(userId);

    return RedirectToAction("SignedOut", "Home");
}
```

The confirmation page view (returned by `ConfirmDelete()` at line 21) must include a form that POSTs to the new endpoint:

```html
@{
    ViewData["Title"] = "Delete Account";
}

<h1>Confirm Account Deletion</h1>
<p>This action cannot be undone. Are you sure?</p>

<form method="post" action="@Url.Action("DeleteAccount", "Account")">
    @Html.AntiForgeryToken()
    <button type="submit" class="btn btn-danger">Yes, delete my account</button>
    <a href="@Url.Action("Index", "Home")" class="btn btn-secondary">Cancel</a>
</form>
```

## Explanation

The original code uses HTTP GET to handle account deletion, which violates CSRF protection because browsers automatically include session cookies on any cross-site GET request. The fix moves the state-changing operation to POST and adds `[ValidateAntiForgeryToken]`, which requires the request to include a server-generated anti-forgery token. ASP.NET Core's framework automatically validates the token before the action executes, rejecting requests from attackers who cannot obtain the token. The `confirmed` parameter is removed because the user now explicitly submits a form to confirm deletion, providing stronger verification intent than a URL parameter. The initial GET endpoint (`ConfirmDelete`) remains unchanged to maintain the link flow from navigation menus or emails.

## Behaviour changes

- **Link navigation**: Existing links to `GET /account/delete?confirmed=true` will no longer trigger deletion. Instead, users navigate to `GET /account/delete/confirm`, which renders a confirmation form they must submit via POST.
- **API contract**: The deletion operation now requires a POST request with an anti-forgery token header or form field. Any automated scripts or API calls that sent GET requests must be updated.
- **Session binding**: The anti-forgery token binds to the authenticated session, so tokens cannot be reused across sessions or users.
- **User experience**: Deletion now requires two steps (navigate to confirmation page, submit form) instead of one click, providing stronger confirmation and preventing accidental deletes via mistyped URLs.
