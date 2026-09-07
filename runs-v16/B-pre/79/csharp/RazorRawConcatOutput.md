## Verdict

Fix required. The code concatenates untrusted user input directly into HTML without encoding, creating a Cross-Site Scripting (CWE-79) vulnerability.

## Source

- **Line 10**: `string orderId = Request.Query["orderId"];` — untrusted query parameter
- **Line 11**: `string customerNote = Request.Query["note"];` — untrusted query parameter

## Fix

```csharp
using Microsoft.AspNetCore.Mvc;
using System.Net;

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

The vulnerability occurs because `orderId` and `customerNote` from the query string are concatenated directly into HTML without encoding. An attacker can inject malicious JavaScript by supplying payloads like `?orderId=<script>alert('xss')</script>`, which executes in victim browsers.

The fix applies `WebUtility.HtmlEncode()` to both untrusted values before insertion into the HTML string. This encodes dangerous characters (`<`, `>`, `&`, quotes) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), preventing browser interpretation as markup or script. The encoding is context-appropriate for HTML body text and preserves the data while making it safe for rendering.

## Behaviour changes

- Legitimate order IDs and customer notes containing `<`, `>`, `&`, or quotes now display as entity-encoded text (e.g., `<` displays as `&lt;`) rather than being interpreted as HTML markup.
- The application now requires the `System.Net` namespace import for `WebUtility`.
