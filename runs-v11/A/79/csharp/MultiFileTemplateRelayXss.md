## Verdict
The application has a reflected cross-site scripting (XSS) vulnerability in the welcome banner rendering logic. User-supplied input from the query parameter flows through the service layer unvalidated and unencoded, then is directly embedded into HTML without neutralization.

## Source
User input originates from `ProfileController.Welcome()` via `Request.Query["nickname"]`. The nickname parameter is extracted at line 21 of ProfileController.cs, passed to `GreetingService.BuildAndRenderBanner()`, which constructs a `BannerContent` object with the nickname as the message. The message field is then used unsafely in `WelcomeBannerRenderer.Write()`.

The call chain is:
1. ProfileController.cs line 21: `string nickname = Request.Query["nickname"].ToString();`
2. GreetingService.cs line 24: `var banner = new BannerContent(trimmedNickname, request.RequestedAt);`
3. WelcomeBannerRenderer.cs line 11: `string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! ...`;

The trimming and truncation applied in GreetingService (lines 18-22) only validate length, not content. They do not prevent XSS.

## Fix
In `WelcomeBannerRenderer.cs`, import `System.Text.Encodings.Web` and use `HtmlEncoder.Default.Encode()` to neutralize the message:

```csharp
using System.Text.Encodings.Web;

public async Task Write(HttpResponse response, BannerContent banner)
{
    response.ContentType = "text/html";
    string html = $"<div class='welcome-banner'>Welcome back, {HtmlEncoder.Default.Encode(banner.Message)}! Last visit logged at {banner.RequestedAt:u}.</div>";
    await response.WriteAsync(html);
}
```

The encoder converts characters such as `<`, `>`, `&`, `"`, and `'` into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the browser from interpreting them as markup or script delimiters.

## Explanation
XSS occurs when untrusted data is embedded into HTML without encoding. In this case, an attacker can craft a URL like `GET /profile/welcome?nickname=<script>alert('xss')</script>` and the injected script will execute in the victim's browser.

Length validation and trimming do not prevent injection—they only limit the payload size. The browser still interprets encoded HTML when it is written unescaped to the response.

HTML entity encoding is the primary defense for output going directly into HTML content. The `HtmlEncoder` class from `System.Text.Encodings.Web` (part of ASP.NET Core and .NET Standard) applies context-appropriate encoding without breaking the surrounding HTML. No changes to the controller or service are required; the fix is localized to the sink—the point where data enters HTML generation—in `WelcomeBannerRenderer.cs`.
