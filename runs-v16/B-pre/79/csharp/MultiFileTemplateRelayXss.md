## Verdict

Exploitable. Untrusted user input from the query parameter flows through the call chain to an HTML sink without encoding, allowing XSS injection.

## Source

`Request.Query["nickname"]` (ProfileController.cs, line 21) — untrusted query parameter

Data flows: `ProfileController.Welcome()` → `GreetingRequest.Nickname` → `GreetingService.BuildAndRenderBanner()` → `BannerContent.Message` → `WelcomeBannerRenderer.Write()` → string interpolation (line 11) → `response.WriteAsync()` (line 14).

The intermediate truncation to 60 characters (GreetingService.cs, lines 19–22) is length validation, not XSS validation, and does not break the taint path.

## Fix

**Vulnerable code (WelcomeBannerRenderer.cs, line 11):**
```csharp
string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";
```

**Fixed code:**
```csharp
using System.Text.Encodings.Web;

public async Task Write(HttpResponse response, BannerContent banner)
{
    response.ContentType = "text/html";
    string html = $"<div class='welcome-banner'>Welcome back, {HtmlEncoder.Default.Encode(banner.Message)}! Last visit logged at {banner.RequestedAt:u}.</div>";

    await response.WriteAsync(html);
}
```

## Explanation

The `banner.Message` value is untrusted user input that was interpolated directly into an HTML string without encoding. By wrapping it with `HtmlEncoder.Default.Encode()`, special HTML characters (`<`, `>`, `&`, `"`, etc.) are converted to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), ensuring the value is treated as text data rather than executable HTML. The `HtmlEncoder` class is part of the standard `System.Text.Encodings.Web` namespace in ASP.NET Core and applies HTML body encoding appropriate for this context. This closes the XSS injection path while preserving the output format and legitimate content display.

## Behaviour changes

The output for legitimate input (e.g., "Alice Smith") remains visually identical. For attacker input containing HTML metacharacters or script tags (e.g., `<img src=x onerror="alert('XSS')">`), those characters are now encoded and rendered as plain text in the browser rather than executed as markup. This is the intended security fix and does not constitute a regression — it is the correct behaviour for displaying untrusted content in HTML. The `WriteAsync()` method contract is unchanged: it still writes the encoded HTML string to the response synchronously with the same error handling.
