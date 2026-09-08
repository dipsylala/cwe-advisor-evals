## Verdict

Confirmed. The vulnerability exists at line 14 of WelcomeBannerRenderer.cs. User-supplied input from the `nickname` query parameter flows through the call chain without sanitization and is directly interpolated into the HTML response, enabling XSS injection.

## Source

The taint originates in `ProfileController.Welcome()` at line 21 where `Request.Query["nickname"]` is read directly from the query string. Although the value is truncated to 60 characters in `GreetingService.BuildAndRenderBanner()`, truncation does not neutralize HTML metacharacters. The value flows through `BannerContent.Message` to the HTML interpolation at line 11 of WelcomeBannerRenderer.cs, and is then written to the HTTP response at line 14 without encoding.

## Fix

### File: WelcomeBannerRenderer.cs

```csharp
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            string encodedMessage = System.Net.WebUtility.HtmlEncode(banner.Message);
            string html = $"<div class='welcome-banner'>Welcome back, {encodedMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            await response.WriteAsync(html);
        }
    }
}
```

## Explanation

The fix applies HTML encoding to `banner.Message` using `System.Net.WebUtility.HtmlEncode()` before the value is interpolated into the HTML string. This encodes special HTML metacharacters (`<`, `>`, `&`, `"`, `'`) so that they are rendered as harmless text rather than parsed as HTML tags or attributes. An input such as `<script>alert('xss')</script>` becomes `&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;`, which the browser displays as literal text instead of executing as code. The `RequestedAt` timestamp is safe because `DateTime` formatting produces only numeric and punctuation characters; only the user-supplied `Message` requires encoding.
