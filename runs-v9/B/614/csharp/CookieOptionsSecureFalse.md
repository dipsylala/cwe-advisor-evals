## Verdict

Exploitable. CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute), confidence: high.

## Source

`CookieOptionsSecureFalse.cs`, `RememberMe` action (`AccountController`, route `POST /account/remember-me`): the `authToken` parameter is bound `[FromQuery]` and carries an authentication/remember-me token. This value is written into a cookie named `AuthToken` at the sink below. The `CookieOptions` built at lines 12-16 sets `HttpOnly = true` and `Expires`, but never sets `Secure`, so it defaults to `false`.

## Fix

Sink: `Response.Cookies.Append("AuthToken", authToken, options)` at line 19, using the `CookieOptions` instance built at lines 12-16.

Sink contract: `Response.Cookies.Append` returns `void`; it appends a `Set-Cookie` header to the outgoing response using the supplied `CookieOptions` and returns nothing to the caller, so no return-value handling changes. It throws `ArgumentNullException` if `key` or `options` is null, which is unaffected by this change. No output is discarded. The only implicit-default argument relevant to this finding is `CookieOptions.Secure`, which defaults to `false` when unset - that is the weakness.

Vulnerable code:

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Expires = DateTimeOffset.UtcNow.AddDays(30)
    // SAST FINDING: CWE-614 - Secure not set, so this cookie can be sent over plaintext HTTP
};

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

`CookieOptions.Secure` defaults to `false`, so the `AuthToken` cookie set at line 19 was eligible for transmission over plaintext HTTP as well as HTTPS, exposing a long-lived (30-day) authentication token to interception on an unencrypted connection. Adding `Secure = true` to the `CookieOptions` instructs the browser to send this cookie only over HTTPS, closing that exposure. This is a per-cookie fix at the identified sink; it does not by itself guarantee the application is served exclusively over HTTPS - that requires a site-wide policy (`CookiePolicyOptions.Secure = CookieSecurePolicy.Always`, `UseHsts()`, `UseHttpsRedirection()`) which is outside this single file and this finding's scope.

## Behaviour changes

None beyond closing the weakness. `Secure = true` is the only field added; `HttpOnly`, `Expires`, the cookie name, and the cookie value are unchanged, and the call's return value (`void`) and error behaviour are unaffected. Under plaintext HTTP the browser will now decline to send this cookie back to the server on subsequent requests - this is the intended effect of the fix, not an incidental side effect, and only affects clients connecting over HTTP, which the cookie should not be trusted over in the first place.

Assumption: `authToken` being bound via `[FromQuery]` (a token in the URL/query string) is a separate weakness (e.g. token exposure in server logs, browser history, or Referer headers) outside the scope of this CWE-614 finding and was not altered.
