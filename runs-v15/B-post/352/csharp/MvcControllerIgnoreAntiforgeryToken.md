## Verdict

Exploitable.

## Source

An attacker crafts an HTTP POST request to the `/Account/UpdateSettings` endpoint from an attacker-controlled origin (e.g., via a hidden form on their website). The request carries the victim's session cookie due to browser cookie handling and the absence of CSRF token validation.

## Fix

**Vulnerable code (line 47):**
```csharp
    [HttpPost]
    // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

**Fixed code:**
```csharp
    [HttpPost]
    public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

Remove the `[IgnoreAntiforgeryToken]` attribute to re-enable ASP.NET Core's automatic CSRF token validation through the app-wide `AutoValidateAntiforgeryTokenAttribute` filter (as described in the method comment).

## Explanation

The `[IgnoreAntiforgeryToken]` attribute on line 47 explicitly disables CSRF protection for this state-changing POST endpoint. The comment confirms this was a temporary workaround during a legacy AJAX client migration that was never cleaned up. By removing this attribute, the ASP.NET Core anti-forgery middleware (configured globally via `AutoValidateAntiforgeryTokenAttribute`) will validate the CSRF token on every incoming request before the action handler executes. Since the endpoint modifies security-sensitive state (the user's email address), the token validation prevents forged requests from succeeding regardless of whether the victim's session cookie is present—the attacker cannot obtain the server-generated token bound to the user's session.

## Behaviour changes

None. Removing the `[IgnoreAntiforgeryToken]` attribute simply re-enables the protection that was already configured at the application level. The middleware validates the token automatically; no changes to the action handler logic or return contract are required.

