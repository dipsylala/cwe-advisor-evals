## Verdict

Confirmed. The application has a Cross-site Scripting (CWE-79) vulnerability. User-supplied input from the `nickname` query parameter flows through `ProfileController` → `GreetingService` → `WelcomeBannerRenderer` and is interpolated directly into HTML markup without sanitization, allowing an attacker to inject malicious scripts.

## Source

The vulnerability originates in `ProfileController.cs` line 21, where the `nickname` query parameter is read directly from `Request.Query["nickname"]` without encoding. This untrusted data flows through `GreetingService.BuildAndRenderBanner()` (which only performs length truncation and trimming) to `WelcomeBannerRenderer.Write()`, where it is embedded in an HTML string at line 11 and written to the HTTP response at line 14.

The data path: `Request.Query["nickname"]` → `GreetingRequest.Nickname` → `BannerContent.Message` → interpolated into HTML string → `response.WriteAsync()`.

## Fix

In `WelcomeBannerRenderer.cs`, HTML-encode the `banner.Message` before inserting it into the HTML template:

```csharp
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            string encodedMessage = HttpUtility.HtmlEncode(banner.Message);
            string html = $"<div class='welcome-banner'>Welcome back, {encodedMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";

            await response.WriteAsync(html);
        }
    }
}
```

The key change is calling `HttpUtility.HtmlEncode(banner.Message)` before interpolating it into the HTML string. This converts special HTML characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents, neutralizing any script tags or event handlers an attacker might inject.

## Explanation

The vulnerability occurs because user input is treated as trusted data in an HTML context. The `nickname` query parameter can contain characters like `<script>alert('xss')</script>`, which when inserted directly into the HTML markup, are interpreted as code by the browser rather than literal text.

HTML encoding is the correct primary defence for this sink. It converts reserved HTML characters into harmless entity references: `<` becomes `&lt;`, `>` becomes `&gt;`, and so on. This ensures the browser treats the content as text, not markup or script.

The `RequestedAt` field does not require encoding because it comes from a server-controlled `DateTime` object and is formatted using the `u` format specifier (UTC ISO 8601), which produces predictable, non-injectable output.

`System.Web.HttpUtility` is the standard .NET utility for HTML encoding and is available in both .NET Framework and .NET Core/.NET 5+. This fix prevents XSS without requiring framework changes or additional dependencies.
