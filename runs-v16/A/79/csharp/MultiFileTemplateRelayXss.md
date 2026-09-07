## Verdict

The vulnerability is confirmed. Line 14 in `WelcomeBannerRenderer.cs` writes user-controlled input directly into an HTML context without encoding, creating an XSS sink.

## Source

The call chain originates in `ProfileController.Welcome()`, where the `nickname` query parameter is read directly from user input and flows through `GreetingService.BuildAndRenderBanner()` into `WelcomeBannerRenderer.Write()`. The `BannerContent.Message` property carries this untrusted data to the vulnerable sink at line 14.

## Fix

In `WelcomeBannerRenderer.cs`, add the `using System.Net;` directive and encode the message:

```csharp
using System;
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

## Explanation

The fix applies HTML encoding to the message before inserting it into the HTML string. `System.Net.WebUtility.HtmlEncode()` converts special HTML characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents, preventing the browser from interpreting attacker-supplied markup or script tags as code. This is the standard mitigation for reflected XSS in dynamically constructed HTML in .NET applications. The encoding is applied at the sink where the data enters the HTML context, which is the appropriate location to enforce this defence.
