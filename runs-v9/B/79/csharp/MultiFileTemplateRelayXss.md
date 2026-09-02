## Verdict

exploitable (confidence: high)

## Source

`ProfileController.Welcome()` reads the `nickname` query-string parameter via `Request.Query["nickname"].ToString()` (defaulted to `"Guest"` only when null/whitespace). This value is wrapped in a `GreetingRequest` and passed to `GreetingService.BuildAndRenderBanner`, which trims it and truncates it to 60 characters (`trimmedNickname`) but performs no HTML-neutralizing transformation - trimming and length-limiting do not remove or encode `<`, `>`, `"`, `'`, or `&`. The trimmed value is wrapped in a `BannerContent` and passed to `WelcomeBannerRenderer.Write`.

## Fix

Sink: `WelcomeBannerRenderer.cs` line 14, `await response.WriteAsync(html);`, where `html` is built by directly interpolating `banner.Message` (the attacker-controlled nickname) into an HTML string at line 11. `HttpResponse.WriteAsync()` is a listed taint sink for CWE-79 in C# outside Razor's auto-encoding, since this code hand-builds the response body rather than rendering through a `.cshtml` view.

Sink contract: `WriteAsync(string)` returns a `Task` that the caller awaits for completion; it does not return or discard any value derived from its input. It takes no encoding-related parameter (UTF-8 is implicit and unrelated to HTML escaping) and throws only on infrastructure failure (e.g. response already started/disposed) - none of that is affected by the fix. `banner.RequestedAt` is a `DateTime` value formatted with `:u`, not attacker-controlled input, so it needs no encoding.

Vulnerable code (`WelcomeBannerRenderer.cs`):

```csharp
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            // VULNERABLE: banner.Message (attacker-controlled nickname) is interpolated into HTML unencoded
            string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";

            await response.WriteAsync(html);
        }
    }
}
```

Fixed code (`WelcomeBannerRenderer.cs`):

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
            string safeMessage = HtmlEncoder.Default.Encode(banner.Message);
            string html = $"<div class='welcome-banner'>Welcome back, {safeMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";

            await response.WriteAsync(html);
        }
    }
}
```

## Explanation

The nickname flows from the query string through `ProfileController` and `GreetingService` unmodified with respect to HTML metacharacters - the only transformations applied (`Trim()`, length truncation to 60 chars) constrain length and whitespace, not markup content, so a value like `<script>alert(1)</script>` or `"><img src=x onerror=alert(1)>` reaches `WelcomeBannerRenderer.Write` intact and is interpolated straight into the HTML response body written by `HttpResponse.WriteAsync()`. The fix encodes `banner.Message` with `HtmlEncoder.Default.Encode()` from `System.Text.Encodings.Web` immediately before it is embedded in the HTML string, at the point the value crosses into the HTML body context - matching the C# guidance's recommendation for encoding untrusted data in hand-built responses outside Razor. This turns any HTML metacharacters in the nickname into their entity-encoded equivalents (`<` becomes `&lt;`, etc.), so the browser renders them as literal text rather than executing them as markup, while normal nicknames render unchanged.

## Behaviour changes

None beyond closing the weakness. `WriteAsync` is still called once, still returns/is awaited the same way, still writes the same `Content-Type` and overall HTML structure, and still incorporates `banner.RequestedAt` exactly as before. The only difference is that `banner.Message` is now passed through `HtmlEncoder.Default.Encode()` before interpolation - legitimate nicknames without HTML metacharacters render identically; a nickname containing `<`, `>`, `&`, `"`, or `'` now displays those characters literally (e.g. `&lt;`) instead of being parsed as markup, which is the intended effect of the fix.
