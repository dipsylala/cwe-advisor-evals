## Verdict

Exploitable

## Source

`Request.Query["nickname"]` (ProfileController.cs:21) — untrusted user input from HTTP query parameter, flows through GreetingService to WelcomeBannerRenderer without encoding.

## Fix

**Vulnerable code:**
```csharp
string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";

await response.WriteAsync(html);
```

**Fixed code:**
```csharp
using System.Text.Encodings.Web;

public async Task Write(HttpResponse response, BannerContent banner)
{
    response.ContentType = "text/html";
    string encodedMessage = HtmlEncoder.Default.Encode(banner.Message);
    string html = $"<div class='welcome-banner'>Welcome back, {encodedMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";

    await response.WriteAsync(html);
}
```

## Explanation

The vulnerability occurs because `banner.Message` — which originates from untrusted user input in the query parameter `nickname` — is embedded directly into an HTML string without output encoding. An attacker can inject malicious script payloads (e.g., `<script>alert('XSS')</script>` or `<img onerror=alert(1)>`) through the nickname parameter, and they will execute in the victim's browser.

The fix applies context-specific HTML encoding using `System.Text.Encodings.Web.HtmlEncoder.Default.Encode()` immediately before embedding the message into the HTML. This converts dangerous characters (`<`, `>`, `&`, `"`, etc.) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), so any attacker-supplied content is rendered as text data rather than executable markup. The `RequestedAt` field is already safe — it is a `DateTime` formatted with a standard date format specifier, not user-supplied input.

## Behaviour changes

None. The `HtmlEncoder.Default.Encode()` call transforms the message string to escape HTML metacharacters, which is necessary for safe rendering. The rest of the method contract remains unchanged: the response is still written asynchronously to the HTTP response stream with the same `ContentType` header. Legitimate content containing `<`, `&`, and quotes will continue to render correctly, displayed as escaped text rather than markup.
