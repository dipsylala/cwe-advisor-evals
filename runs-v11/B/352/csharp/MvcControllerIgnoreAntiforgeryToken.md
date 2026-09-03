## Verdict

Exploitable. The `UpdateSettings` action explicitly disables CSRF token validation via `[IgnoreAntiforgeryToken]`, allowing attackers to forge POST requests that modify authenticated user settings without the user's knowledge.

## Source

External attacker crafting a cross-site POST request targeting the UpdateSettings endpoint. The request is delivered when an authenticated victim visits an attacker-controlled page, causing the victim's session cookie to be sent automatically with the forged request.

## Fix

**Vulnerable code:**
```csharp
    [HttpPost]
    // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

**Fixed code:**
```csharp
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

## Explanation

The `[IgnoreAntiforgeryToken]` attribute explicitly disables the built-in CSRF protection that ASP.NET Core provides. Replacing it with `[ValidateAntiForgeryToken]` restores the required server-side validation of anti-forgery tokens on this state-changing operation. The framework will now reject POST requests that do not include a valid token bound to the authenticated user's session, preventing forged requests from reaching the endpoint. Since the UpdateSettings action modifies user data (email address) and is already decorated with `[Authorize]`, applying the CSRF token validation is essential to confirm the request originated from the application itself rather than a malicious third party.

## Behaviour changes

None. Token validation is an additive security control that does not change the action's contract, return values, or error handling. It only adds a required header or form field check before processing continues. Forms and AJAX clients must include the anti-forgery token (via `@Html.AntiForgeryToken()` in views or the `RequestVerificationToken` header in JavaScript), but this is the intended behavior that was bypassed by the now-removed `[IgnoreAntiforgeryToken]` attribute.
