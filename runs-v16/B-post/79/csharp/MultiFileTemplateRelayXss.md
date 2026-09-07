## Verdict

VULNERABLE. The code passes untrusted user input directly into HTML without encoding, allowing XSS injection.

## Source

User-controlled `nickname` query parameter flows from `ProfileController.Welcome()` → `GreetingService.BuildAndRenderBanner()` → `WelcomeBannerRenderer.Write()` without HTML encoding applied.

The sink is `HttpResponse.WriteAsync(html)` at line 14 of WelcomeBannerRenderer.cs.

## Fix

**Add namespace import:**
```csharp
using System.Text.Encodings.Web;
```

**Replace the vulnerable method in WelcomeBannerRenderer.cs:**

From:
```csharp
public async Task Write(HttpResponse response, BannerContent banner)
{
    response.ContentType = "text/html";
    string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";
    await response.WriteAsync(html);
}
```

To:
```csharp
public async Task Write(HttpResponse response, BannerContent banner)
{
    response.ContentType = "text/html";
    string encodedMessage = HtmlEncoder.Default.Encode(banner.Message);
    string html = $"<div class='welcome-banner'>Welcome back, {encodedMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";
    await response.WriteAsync(html);
}
```

## Explanation

The fix applies HTML entity encoding to `banner.Message` before embedding it in the HTML string. `HtmlEncoder.Default.Encode()` converts characters with special meaning in HTML (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that user-supplied data is treated as text content, not executable markup. An attacker payload like `<img src=x onerror="alert('xss')">` is rendered as literal text and does not execute in the browser.

The encoding is applied at the output sink (the HTML construction point) rather than at input, following the principle that encoding context matters: a value safe in HTML body text differs from one safe in a script block or URL. The `RequestedAt` field is left unencoded because it is constructed by the application (DateTime.UtcNow formatted with a standard format string), not from user input.

## Behaviour changes

- User input containing HTML metacharacters now appears as escaped entities in the rendered page (e.g., `<` displays as `&lt;`).
- Legitimate content containing `<`, `>`, `&`, quotes, or other HTML-special characters now renders correctly without being interpreted as markup.
- The response Content-Type remains `text/html` and the overall page structure is unchanged; only the dynamic message content is sanitized.
