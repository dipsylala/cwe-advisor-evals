## Verdict

Exploitable. The `DeleteAccount` action is a GET endpoint that performs a state-changing operation (account deletion) without CSRF token validation. An attacker can force an authenticated user to delete their account by embedding a malicious URL in an image, iframe, or form on an external site, and the browser will automatically attach the session cookie to the request.

## Source

Attacker-controlled URL crafted to trigger `GET /account/delete?confirmed=true` on the victim's authenticated session.

## Fix

**Vulnerable code (line 32):**
```csharp
[HttpGet("delete")]
public async Task<IActionResult> DeleteAccount(bool confirmed)
```

**Fixed code:**
```csharp
[HttpPost("delete")]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteAccount(bool confirmed)
```

The `confirmed` parameter remains to receive the form value from the confirmation page's POST form, which must include `@Html.AntiForgeryToken()` to supply the anti-forgery token to the server.

## Explanation

Changing from `[HttpGet]` to `[HttpPost]` moves the state-changing action from a safe HTTP method (which cannot be protected by CSRF middleware) to a safe method where CSRF protection is enforced. The `[ValidateAntiForgeryToken]` attribute instructs ASP.NET Core to reject the request unless it carries a valid anti-forgery token bound to the user's session. Attackers cannot obtain this token because it is cryptographically random and unique per session, so embedding a malicious link or image tag cannot trigger the deletion. The confirmation page (which renders at `GET /account/delete/confirm`) remains accessible without a token, allowing users to reach the confirmation form. The form on that page must POST to this endpoint with the token included via `@Html.AntiForgeryToken()`.

## Behaviour changes

- The endpoint now requires POST instead of GET. Existing bookmarks, direct GET requests, or navigation links that pointed to `/account/delete` will fail with a 405 Method Not Allowed error. This is the intended security fix: state changes must be submitted via forms or AJAX, not plain links.
- The `confirmed` parameter is now sent as form data (POST body) instead of a query string parameter. Applications using query string binding must ensure the form includes a hidden input field with name="confirmed" value="true" (or equivalent), which is standard practice for confirmation forms.
- No changes to the return values, exception handling, or business logic. The redirect and authorization flow remain intact.
