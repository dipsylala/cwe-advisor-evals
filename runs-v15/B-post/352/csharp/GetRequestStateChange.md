## Verdict
exploitable

## Source
HTTP GET request to `/account/delete?confirmed=true` from an attacker-controlled origin. The `confirmed` parameter and authenticated session are supplied by the attacker via the victim's browser.

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

## Explanation
The endpoint performs a state-changing operation (account deletion) but is routed to GET, which is unprotected by ASP.NET Core's CSRF middleware. The middleware validates only POST, PUT, and DELETE methods, so any GET request—including one triggered by a malicious link, image tag, or iframe—bypasses the middleware without token verification.

The fix changes the method to POST and adds `[ValidateAntiForgeryToken]`, which enforces that the request must carry a valid anti-forgery token issued by the server and bound to the user's session. This closes the CSRF vulnerability. The existing `ConfirmDelete` GET endpoint remains unchanged to render the confirmation form; the form's POST action must target the now-protected `/account/delete` endpoint and include `@Html.AntiForgeryToken()` to generate and submit the token. (The view is not modified in this output per scope rules.)

## Behaviour changes
- Method changed from GET to POST: Required to bring the route under CSRF middleware validation. GET requests to this endpoint will now fail with a 405 Method Not Allowed response, enforcing that state-changing requests come from submitted forms with CSRF tokens, not from direct links or embedded resources.
- `[ValidateAntiForgeryToken]` attribute added: Required to validate the anti-forgery token present in POST form data. Requests without a valid token bound to the user's session will be rejected with a 400 Bad Request response.
- The `confirmed` parameter now comes from POST form data instead of URL query string: Required for POST semantics; the parameter value is extracted from form fields rather than query parameters. The confirmation form in the ConfirmDelete view must include a hidden or checkbox field named `confirmed` with value `true` for the flow to work.
