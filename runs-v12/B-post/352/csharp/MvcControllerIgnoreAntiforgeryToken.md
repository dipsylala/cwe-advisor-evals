## Verdict

Exploitable. The `[IgnoreAntiforgeryToken]` attribute at line 47 explicitly disables CSRF token validation on the `UpdateSettings` POST action, which modifies authenticated user account data (email). An attacker can craft a malicious request that forces an authenticated user to change their email without their consent.

## Source

Attacker-controlled request submitted to the `UpdateSettings` POST endpoint while an authenticated user visits a malicious website. The request body contains a new email address in `AccountSettingsRequest.NewEmail`.

## Fix

**Vulnerable Code (line 45–48):**
```csharp
[HttpPost]
// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
[IgnoreAntiforgeryToken]
public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

**Fixed Code:**
```csharp
[HttpPost]
public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

## Explanation

Remove the `[IgnoreAntiforgeryToken]` attribute from the `UpdateSettings` action. The comment in the existing code states this attribute was added as a temporary override during legacy AJAX client migration and was never removed. The application's app-wide `AutoValidateAntiforgeryTokenAttribute` filter is configured to validate CSRF tokens on all POST/PUT/DELETE actions by default. Removing this attribute re-enables automatic CSRF token validation, requiring a server-issued token to be present in all requests to this endpoint. This prevents attackers from forging requests on behalf of authenticated users because they cannot obtain the cryptographically random token bound to the victim's session.

## Behaviour changes

None. The endpoint will now require a valid CSRF token in state-changing requests, which is the correct and intended security behavior for any authenticated POST action that modifies user data. The client (forms and AJAX requests) must already include the token via `@Html.AntiForgeryToken()` in forms or the `RequestVerificationToken` header in AJAX calls, as required by the global anti-forgery configuration. Removing the override restores this validation, making the endpoint secure against CSRF while preserving all existing legitimate request handling.
