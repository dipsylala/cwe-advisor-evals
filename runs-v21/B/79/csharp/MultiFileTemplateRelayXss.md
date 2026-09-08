## Verdict

exploitable

## Source

Line 21 in ProfileController.cs: `Request.Query["nickname"]` – untrusted user input from query string parameter.

## Fix

### File: WelcomeBannerRenderer.cs

```csharp
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Text.Encodings.Web;

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

The vulnerability exists because `banner.Message` is directly interpolated into an HTML string without encoding, then written to the HTTP response via `response.WriteAsync()` on line 14. This allows an attacker to inject malicious JavaScript through the query parameter, for example `?nickname=<script>alert('xss')</script>` or other event-handler attributes. The data flows from the untrusted query parameter through ProfileController, GreetingService, and BannerContent to reach the sink unencoded.

The fix applies context-specific HTML encoding using `HtmlEncoder.Default.Encode()` from the `System.Text.Encodings.Web` namespace. This encodes special HTML characters (such as `<`, `>`, `&`, `"`, and `'`) into their corresponding HTML entities, preventing the browser from interpreting the injected content as executable code. The fix preserves the legitimate HTML structure and content of the page while neutralizing any XSS payload.

## Behaviour changes

Added import `using System.Text.Encodings.Web;` – this is a standard library namespace available in .NET Core 2.1 and all subsequent versions. Changed line 11 to wrap `banner.Message` with `HtmlEncoder.Default.Encode()` before interpolation. The sink contract is preserved: `response.WriteAsync()` receives a string parameter as before; only the contents of that string are changed to encode untrusted data. No change to method signature, return type, or async behavior.

