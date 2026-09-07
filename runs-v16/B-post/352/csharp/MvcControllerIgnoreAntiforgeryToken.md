## Verdict

Exploitable. The `[IgnoreAntiforgeryToken]` attribute on line 47 explicitly disables CSRF protection for an authenticated state-changing endpoint that modifies user account settings.

## Source

HTTP POST request to the `UpdateSettings` action from any origin, carrying an authenticated session cookie.

## Fix

Remove the `[IgnoreAntiforgeryToken]` attribute from the `UpdateSettings` action.

**Vulnerable code:**
```csharp
    [HttpPost]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

**Fixed code:**
```csharp
    [HttpPost]
    public async Task<IActionResult> UpdateSettings(AccountSettingsRequest request)
```

## Explanation

The endpoint performs a state-changing operation (updating the user's email address) on an authenticated user. The `[IgnoreAntiforgeryToken]` attribute explicitly exempts this endpoint from CSRF token validation, allowing any attacker-controlled request carrying the user's session cookie to modify the account. The comment indicates this attribute was meant to be temporary during a legacy AJAX client migration but was never removed. Deleting the attribute re-enables the application's global anti-forgery filter (via `AutoValidateAntiforgeryTokenAttribute`), which will require a valid CSRF token before processing state-changing requests.

## Behaviour changes

None. Removing the attribute does not alter the action's signature, parameters, return value, or logic. It simply re-enables the CSRF protection that the application's global configuration already intends to apply to all POST/PUT/DELETE actions.
