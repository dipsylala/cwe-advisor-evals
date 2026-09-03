## Verdict

Exploitable. The `DeleteAccount` action uses `[HttpGet]` for a state-changing operation, which bypasses CSRF middleware entirely. An attacker can forge a request (via `<img>`, `<iframe>`, or auto-navigated link) that deletes the victim's account without their knowledge.

## Source

Query string parameter `confirmed` (line 33), accepted without CSRF token validation. The attacker-controlled value flows to `_accountService.DeleteAccountAsync(userId)` (line 41), a state-changing sink.

## Fix

**Vulnerable code (line 32-44):**

```csharp
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
```

**Fixed code:**

```csharp
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
```

## Explanation

The fix changes the HTTP method from `[HttpGet]` to `[HttpPost]` and adds the `[ValidateAntiForgeryToken]` attribute. GET requests bypass CSRF middleware because browsers send them automatically in cross-site contexts (images, iframes, navigation); POST requests require the client to explicitly include the anti-forgery token, which an attacker cannot obtain cross-site. The token is cryptographically random (128 bits via `RandomNumberGenerator`), bound to the authenticated user, and validated in constant time by the framework. This prevents the attacker from forging a valid deletion request.

The confirmation parameter `confirmed` continues to accept a bool, but now it must be sent via POST body or query parameter bound in the POST request, not the query string alone. The confirmation page's form must include `@Html.AntiForgeryToken()` to embed the token.

## Behaviour changes

**HTTP method change:** `GET` to `POST`. Callers must now make an explicit POST request instead of a simple GET navigation. The confirmation page must use a form with `method="post"` and include the anti-forgery token via `@Html.AntiForgeryToken()`. Any direct URL navigation (bookmarks, links) will no longer work; users must use the form.

**Token validation:** ASP.NET Core's antiforgery middleware now validates the request. Without a valid `__RequestVerificationToken` in the request (from form data or the configured header), the action returns HTTP 400. This is the intended behaviour to prevent CSRF attacks.

**No changes to return values, arguments (the `confirmed` parameter remains), or service call logic.**
