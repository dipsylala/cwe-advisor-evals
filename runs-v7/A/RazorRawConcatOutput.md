## Verdict

**CWE-79 Confirmed**: Unsanitized query parameters are concatenated into HTML returned via `Content()` with `text/html` content type, enabling script injection.

## Source

Query parameters `orderId` and `customerNote` obtained from `Request.Query` (lines 10-11) are directly concatenated into an HTML string (lines 15-16) without encoding. The concatenated HTML is returned as a raw response via `Content(html, "text/html")` (line 20), allowing injected scripts to execute in the client's browser.

## Fix

Use `System.Text.Encodings.Web.HtmlEncoder.Default.Encode()` to encode both query parameters before concatenating them into the HTML string:

```csharp
using System.Text.Encodings.Web;
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
                "<p>Order: " + HtmlEncoder.Default.Encode(orderId) + "</p>" +
                "<p>Note from customer: " + HtmlEncoder.Default.Encode(customerNote) + "</p>" +
                "</body></html>";

            return Content(html, "text/html");
        }
    }
}
```

## Explanation

HTML encoding converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entity references (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), which are rendered as literal text by the browser rather than interpreted as HTML or JavaScript syntax. This prevents script injection while preserving the intended content for display. `HtmlEncoder` is part of the standard .NET framework (no additional dependencies required) and is the recommended approach for encoding untrusted data destined for HTML context in ASP.NET Core.
