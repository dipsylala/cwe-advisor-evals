## Verdict

Confirmed. Reflected cross-site scripting: the `nickname` query-string parameter flows unencoded into an HTML response body.

## Source

`ProfileController.Welcome()` reads `Request.Query["nickname"]` (line 21 of `ProfileController.cs`) directly from the HTTP request. It falls back to `"Guest"` only when empty/whitespace, then wraps it in a `GreetingRequest` and passes it to `GreetingService.BuildAndRenderBanner`.

`GreetingService.BuildAndRenderBanner` (`GreetingService.cs`) only trims whitespace and truncates to 60 characters (lines 18-22) - no HTML encoding or character filtering - before placing the value into `BannerContent.Message` and forwarding to `WelcomeBannerRenderer.Write`.

`WelcomeBannerRenderer.Write` (`WelcomeBannerRenderer.cs`, line 11) interpolates `banner.Message` directly into an HTML string via `$"..."`, and line 14 writes that string to the HTTP response with `response.WriteAsync(html)`, which is the sink. Trimming and length-capping do not neutralize HTML metacharacters, so a request such as `/profile/welcome?nickname=<script>alert(1)</script>` (36 characters, well under the 60-character cap) reaches the browser unescaped and executes.

## Fix

Encode the untrusted value at the point it is written into HTML, in `WelcomeBannerRenderer.cs`:

```csharp
using System.Threading.Tasks;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            string safeMessage = HtmlEncoder.Default.Encode(banner.Message);
            string html = $"<div class='welcome-banner'>Welcome back, {safeMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";

            await response.WriteAsync(html);
        }
    }
}
```

`System.Text.Encodings.Web.HtmlEncoder.Default` (part of the .NET base class library, no extra package) converts `<`, `>`, `&`, `"`, `'` and other HTML-significant characters into their entity equivalents, so injected markup renders as inert text instead of being parsed as tags. Encoding is applied at the renderer, the single point that emits HTML, rather than upstream in `GreetingService` or `ProfileController` - this keeps `BannerContent.Message` holding the plain, un-encoded value for any other consumer (logging, non-HTML use) and avoids double-encoding if the renderer is later reused.

The `RequestedAt` value is a server-generated `DateTime` formatted with `:u`, not attacker-controlled, so it does not need encoding.

## Explanation

This is a classic reflected XSS: user input from a query-string parameter crosses two intermediate layers (controller, service) that apply only cosmetic normalization (trim, length cap) and never contextually encode the value, then lands in raw HTML written straight to the response. Because the sink is a plain HTML string built with C# interpolation rather than a templating engine with autoescaping (e.g. Razor), there is no implicit encoding anywhere in the chain, and the vulnerability is only visible by following the value from the `HttpRequest` source in `ProfileController.cs` through `GreetingService.cs` to the `WriteAsync` sink in `WelcomeBannerRenderer.cs`. Encoding at the sink is the correct fix because it is the last point before the value crosses the trust boundary into the browser, and it works regardless of which upstream caller supplied the message.
