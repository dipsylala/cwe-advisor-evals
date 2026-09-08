## Verdict
The vulnerability is confirmed. Untrusted user input from `Request.Query` is concatenated directly into an HTML string and returned as `text/html` without encoding, allowing cross-site scripting (XSS) injection.

## Source
Lines 10-11: `Request.Query["orderId"]` and `Request.Query["note"]` are untrusted sources accessed directly from the query string with no validation or sanitization.

## Fix
### File: RazorRawConcatOutput.cs

```csharp
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace OrderPortal.Controllers
{
    public class TrackingController : Controller
    {
        [HttpGet("/tracking/confirm")]
        public IActionResult Confirm()
        {
            string orderId = Request.Query["orderId"];
            string customerNote = Request.Query["note"];

            // Encode untrusted input before including in HTML
            string encodedOrderId = HtmlEncoder.Default.Encode(orderId);
            string encodedCustomerNote = HtmlEncoder.Default.Encode(customerNote);

            string html = "<html><body>" +
                "<h2>Tracking Confirmation</h2>" +
                "<p>Order: " + encodedOrderId + "</p>" +
                "<p>Note from customer: " + encodedCustomerNote + "</p>" +
                "</body></html>";

            return Content(html, "text/html");
        }
    }
}
```

## Explanation
The fix adds the `System.Text.Encodings.Web` using directive and encodes the untrusted query parameters using `HtmlEncoder.Default.Encode()` before concatenating them into the HTML string. This context-specific HTML encoding converts dangerous characters like `<`, `>`, `&`, and quotes into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&#x27;`), preventing the browser from interpreting them as HTML or script delimiters. The encoded values remain safe data when rendered in the HTML body context.

## Behaviour changes
- **New dependency**: `System.Text.Encodings.Web` (part of .NET standard library in ASP.NET Core)
- **Input handling**: Query string values that previously would have rendered as raw HTML (e.g., `<script>alert('XSS')</script>`) are now HTML-encoded and render as literal text
- **Output content**: The HTML response still contains the query parameter values but in encoded form, preserving legitimate content containing `<`, `&`, and quotes while blocking script injection
- **No semantic change**: Legitimate tracking order confirmations display correctly; only malicious payloads are neutralized
