## Verdict

The vulnerability is confirmed. User-controlled input flows from the query string through the service layer without HTML encoding, then reaches the response output as a direct string interpolation, creating an XSS sink at line 14 of `WelcomeBannerRenderer.cs`.

## Source

The attack vector originates in `ProfileController.Welcome()` at line 21, where the `nickname` query parameter is read directly from the request:

```csharp
string nickname = Request.Query["nickname"].ToString();
```

This untrusted value is passed through `GreetingService.BuildAndRenderBanner()` where it undergoes length truncation but no HTML encoding. It then flows into `BannerContent.Message`, which reaches the XSS sink.

## Fix

In `WelcomeBannerRenderer.cs`, import the encoding namespace and HTML-encode the message before string interpolation:

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
            string encodedMessage = WebUtility.HtmlEncode(banner.Message);
            string html = $"<div class='welcome-banner'>Welcome back, {encodedMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";

            await response.WriteAsync(html);
        }
    }
}
```

Use `System.Net.WebUtility.HtmlEncode()` to encode the user-controlled message before insertion into the HTML string.

## Explanation

The vulnerability occurs because user input (the nickname from the query string) is embedded directly into dynamically generated HTML without encoding. An attacker can inject script tags or event handlers that execute in the victim's browser.

Encoding converts characters like `<` to `&lt;` and `>` to `&gt;`, preventing the browser from interpreting the injected content as executable code. By applying `HtmlEncode()` to `banner.Message` before the string interpolation on line 11, the malicious payload becomes harmless text that displays literally rather than executing.

`System.Net.WebUtility.HtmlEncode()` is a built-in .NET method available without additional dependencies and is the standard approach for encoding output destined for HTML contexts.
