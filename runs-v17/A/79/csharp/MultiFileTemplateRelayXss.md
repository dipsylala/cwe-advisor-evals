## Verdict

Real issue confirmed. User-controlled query parameter `nickname` flows through the call chain without HTML encoding and is embedded directly into an HTML response via string interpolation, enabling XSS injection.

## Source

**Entry point:** ProfileController.Welcome() reads untrusted input from query string `Request.Query["nickname"]`

**Data flow:**
- ProfileController.Welcome() (line 21): reads `nickname` query param
- Passes to GreetingService.BuildAndRenderBanner() (line 28)
- GreetingService applies only length/format checks—no sanitization (lines 19-22)
- Creates BannerContent with unsanitized message (line 24)
- WelcomeBannerRenderer.Write() embeds message directly into HTML string (line 11)
- WriteAsync outputs HTML to response without encoding (line 14)

**Sink:** WelcomeBannerRenderer.Write() at line 14 (`await response.WriteAsync(html);`)

The entire message flow contains no encoding or sanitization, allowing injection of arbitrary HTML/JavaScript.

## Fix

### File: WelcomeBannerRenderer.cs

```csharp
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Net;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            string html = $"<div class='welcome-banner'>Welcome back, {WebUtility.HtmlEncode(banner.Message)}! Last visit logged at {banner.RequestedAt:u}.</div>";

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            await response.WriteAsync(html);
        }
    }
}
```

## Explanation

The fix applies HTML encoding to `banner.Message` using `System.Net.WebUtility.HtmlEncode()` at the point of output generation. This encodes special characters (`<`, `>`, `&`, `"`, `'`) into HTML entities, preventing browser interpretation as markup or script.

For example:
- Input: `<img src=x onerror=alert('XSS')>`
- Output: `&lt;img src=x onerror=alert(&#39;XSS&#39;)&gt;`
- Browser renders as literal text, not executable code

This defense is applied at the output sink where the HTML is generated, ensuring all message content is neutralized before reaching the response. The `RequestedAt` field requires no encoding as it is a formatted DateTime (controlled and safe by design).

No changes needed to ProfileController or GreetingService; the input validation there (null-check, length truncation) complements output encoding but does not replace it.
