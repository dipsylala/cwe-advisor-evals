## Verdict

Confirmed. `WelcomeBannerRenderer.Write` builds an HTML response by interpolating `banner.Message` directly into a markup string and writing it to the response body unencoded. `banner.Message` originates from the `nickname` query-string parameter in `ProfileController.Welcome`, which only trims whitespace and truncates length in `GreetingService.BuildAndRenderBanner` - neither operation neutralizes HTML metacharacters. A request such as `GET /profile/welcome?nickname=<script>alert(1)</script>` is reflected into the page and executes in the victim's browser.

## Source

`Request.Query["nickname"]` in `ProfileController.Welcome` (ProfileController.cs) flows unmodified in content (only trimmed/truncated) through `GreetingRequest.Nickname` -> `GreetingService.BuildAndRenderBanner` -> `BannerContent.Message` -> `WelcomeBannerRenderer.Write`, where it is interpolated into an HTML string and written via `response.WriteAsync(html)` (WelcomeBannerRenderer.cs, line 14 sink).

## Fix

### File: WelcomeBannerRenderer.cs

```csharp
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            string safeMessage = WebUtility.HtmlEncode(banner.Message);
            string html = $"<div class='welcome-banner'>Welcome back, {safeMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";

            await response.WriteAsync(html);
        }
    }
}
```

## Explanation

The renderer is the sink and the only place in the call chain that emits HTML, so it is the correct place to neutralize the value regardless of which caller supplies it. `WebUtility.HtmlEncode` (from `System.Net`, part of the base class library, no extra dependency) converts `<`, `>`, `&`, `"` and `'` into their entity equivalents, so an injected `<script>` tag or attribute-breakout payload is rendered as inert text inside the `div` rather than parsed as markup. `banner.RequestedAt` is a `DateTime` formatted with the `u` format specifier, which only ever produces digits, `-`, `:` and a space, so it carries no injection risk and does not need encoding. Encoding at the point of HTML output (rather than at the controller or service layer) also keeps `BannerContent.Message` available as plain, unencoded data for any other consumer (e.g. logging, an API response) that should not receive HTML-escaped text.

Verification: request `/profile/welcome?nickname=<script>alert(1)</script>` before the fix and confirm the raw `<script>` tag appears unescaped in the response body; after the fix, confirm the response instead contains `&lt;script&gt;alert(1)&lt;/script&gt;` and no unescaped `<`/`>` characters are present in the rendered output.
