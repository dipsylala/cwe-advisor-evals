## Verdict

exploitable (confidence: high)

The `CookieOptions` instance passed to `Response.Cookies.Append` never sets `Secure`, so it defaults to `false` (absent a global `CookiePolicyOptions.Secure = CookieSecurePolicy.Always` override, which is not present in this file). The resulting `AuthToken` cookie is sent by the browser over both HTTP and HTTPS, exposing a long-lived (30-day) authentication token to interception on any unencrypted connection.

## Source

`RememberMe([FromQuery] string authToken)` at line 10 - `authToken` is an attacker-influenced query-string parameter, used directly as the cookie value with no intermediate transformation.

## Fix

Vulnerable code (`CookieOptionsSecureFalse.cs`, lines 12-19):

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

// SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
Response.Cookies.Append("AuthToken", authToken, options);
```

Fixed code:

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
};

Response.Cookies.Append("AuthToken", authToken, options);
```

## Explanation

Adding `Secure = true` to the `CookieOptions` instructs the browser to withhold the `AuthToken` cookie on any request that is not HTTPS, closing the plaintext-interception path the finding flags. `Response.Cookies.Append` itself is otherwise unchanged: it still returns `void`, still takes the same cookie name and value, and every other option (`HttpOnly`, `Expires`) is preserved as-is. The fix relies on the site enforcing HTTPS end-to-end (e.g. `UseHttpsRedirection()`/`UseHsts()` in `Program.cs`); those are outside this single-file case and are not modified here, but the `Secure` flag is inert without them - it stops the cookie from being sent, not from existing.

## Behaviour changes

- `Secure = true` added to `CookieOptions` - required to close the weakness. Consequence: if this endpoint is ever reached over plain HTTP (e.g., in a local/dev environment without HTTPS), the browser will silently refuse to send the `AuthToken` cookie back on subsequent requests, which will look like the "remember me" cookie not persisting rather than an error. This is the intended tightening, not a regression, but it does mean the fix's effectiveness depends on HTTPS being enforced site-wide.
- No other arguments, return values, or control flow were altered. `HttpOnly`, `Expires`, the cookie name, and the cookie value are unchanged.
