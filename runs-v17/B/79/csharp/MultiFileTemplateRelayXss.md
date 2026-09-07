## Verdict

Confirmed XSS vulnerability. Untrusted user input from the query string flows through the call chain without encoding and is embedded directly into HTML at the response sink.

## Source

User-supplied `nickname` parameter from `Request.Query["nickname"]` in ProfileController.Welcome() (ProfileController.cs:21). The input is only validated for null/whitespace and length-truncated to 60 characters, but no special characters are removed or encoded.

## Fix

### File: WelcomeBannerRenderer.cs

```csharp
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            string html = $"<div class='welcome-banner'>Welcome back, {HtmlEncoder.Default.Encode(banner.Message)}! Last visit logged at {banner.RequestedAt:u}.</div>";

            await response.WriteAsync(html);
        }
    }
}
```

## Explanation

The vulnerability occurs because `banner.Message` (derived from untrusted user input) is embedded directly into an HTML string via interpolation without encoding. An attacker can inject XSS payloads like `<script>alert('xss')</script>` through the query string parameter.

The fix applies HTML encoding at the sink using `HtmlEncoder.Default.Encode()` from `System.Text.Encodings.Web`. This encodes special HTML characters (`<`, `>`, `&`, `"`, `'`) so they are treated as data rather than markup or attributes, preventing script injection. The encoding is applied only to `banner.Message` since `RequestedAt` is a controlled DateTime format that cannot contain user input.

Per the C# CWE-79 guidance, context-specific encoding at the output sink is the primary defense. `HtmlEncoder.Default.Encode()` is safe for HTML body context and produces a `string` that can be interpolated into the HTML template.

## Behaviour changes

The message text will now display HTML special characters literally in the response. For example, if a user enters `<div>`, it will render as the literal text `&lt;div&gt;` in the HTML page rather than being interpreted as a tag. This is the intended behavior for user-supplied content that should not be interpreted as HTML markup.
