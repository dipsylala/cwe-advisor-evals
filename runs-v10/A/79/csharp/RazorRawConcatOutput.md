## Verdict

Confirmed as CWE-79. Untrusted query parameters are concatenated directly into an HTML string and returned as text/html, enabling script injection.

## Source

The vulnerable data flow:

1. Untrusted input sourced from HTTP query parameters: `Request.Query["orderId"]` and `Request.Query["note"]` (lines 10-11)
2. Concatenated directly into an HTML string without encoding (lines 13-17)
3. Returned as HTML content via `Content(html, "text/html")` (line 20)

An attacker can inject malicious scripts by supplying query parameters like `orderId=<script>alert('xss')</script>` or `note=<img src=x onerror=alert('xss')>`.

## Fix

Encode the untrusted input using `System.Text.Encodings.Web.HtmlEncoder` before concatenating it into the HTML string:

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
            string orderId = HtmlEncoder.Default.Encode(Request.Query["orderId"]);
            string customerNote = HtmlEncoder.Default.Encode(Request.Query["note"]);

            string html = "<html><body>" +
                "<h2>Tracking Confirmation</h2>" +
                "<p>Order: " + orderId + "</p>" +
                "<p>Note from customer: " + customerNote + "</p>" +
                "</body></html>";

            return Content(html, "text/html");
        }
    }
}
```

## Explanation

`HtmlEncoder.Default.Encode()` escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents, preventing the browser from interpreting attacker-supplied strings as markup or scripts. An input like `<script>alert('xss')</script>` becomes `&lt;script&gt;alert('xss')&lt;/script&gt;`, rendering it as literal text in the page.

The encoding is applied at the point where untrusted data enters the HTML string, ensuring all user-supplied values are neutralized before the content reaches the browser. This is the primary defense for reflected XSS in server-generated HTML responses.
