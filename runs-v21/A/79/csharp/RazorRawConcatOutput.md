## Verdict
Real - CWE-79 vulnerability confirmed. User-controlled query parameters are concatenated into HTML and returned with content-type `text/html` without encoding, enabling script injection.

## Source
`orderId` and `customerNote` parameters originate from the query string via `Request.Query`, which is untrusted user input in an HTTP request.

## Fix

### File: RazorRawConcatOutput.cs

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
User inputs from `Request.Query` are HTML-encoded using `System.Net.WebUtility.HtmlEncode()` before insertion into the HTML string. This converts special characters like `<`, `>`, `&`, and quotes into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), preventing them from being interpreted as HTML or script tags. The encoding is applied at the point of use, ensuring that any malicious payload in the query parameters is rendered as harmless text rather than executable code. `WebUtility` is part of the .NET Framework and requires the `using System.Net;` namespace.
