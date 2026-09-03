## Verdict

Exploitable. The `[IgnoreAntiforgeryToken]` attribute at line 47 explicitly disables ASP.NET Core's CSRF protection on an authenticated state-changing endpoint. When a victim user visits an attacker-controlled site, the attacker can forge a POST request to `UpdateSettings` with a new email address. The victim's authenticated session cookie is sent automatically, and because CSRF validation is disabled, the email change is processed without token verification, resulting in account compromise.

## Source

Attacker-controlled HTTP POST request. An attacker crafts a forged POST to the `UpdateSettings` endpoint, exploiting the victim's active authenticated session.

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

## Explanation

Remove the `[IgnoreAntiforgeryToken]` attribute. The code comment indicates the attribute was applied as a temporary workaround during a legacy AJAX client migration but was never removed. Since the application is configured with `AutoValidateAntiforgeryTokenAttribute` for global CSRF protection, removing this attribute allows the framework's standard anti-forgery validation to apply to the endpoint. The framework will validate that the `__RequestVerificationToken` is present and matches the session-bound token, preventing forged requests from being processed.

## Behaviour changes

None. The `[IgnoreAntiforgeryToken]` attribute was a bypass added specifically to disable an already-enabled global protection. Removing it restores the protection that should be active according to the application's configuration. All legitimate requests (including AJAX requests) from the same origin that include the required anti-forgery token will continue to work as before.
