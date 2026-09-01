## Verdict

Real vulnerability. Untrusted query parameters are concatenated directly into HTML without encoding, allowing XSS injection.

## Source

Lines 10–11: HTTP query parameters `orderId` and `customerNote` via `Request.Query` are untrusted attacker-controlled values.

## Fix

Replace unencoded query parameters with HTML-encoded versions using `System.Net.WebUtility.HtmlEncode()`:

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
            string orderId = WebUtility.HtmlEncode(Request.Query["orderId"]);
            string customerNote = WebUtility.HtmlEncode(Request.Query["note"]);

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

The fix applies HTML entity encoding to both untrusted query parameters before they are embedded in the HTML markup. `WebUtility.HtmlEncode()` converts characters like `<`, `>`, `&`, `"`, and `'` to their corresponding HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the browser from interpreting them as HTML or script delimiters. An attacker's payload such as `<script>alert('XSS')</script>` is rendered as literal text (`&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;`) rather than executable code. The fix uses the built-in .NET encoding function available in ASP.NET Core without external dependencies, and preserves the original return value and response format.

## Behaviour changes

- Query parameter values containing `<`, `>`, `&`, `"`, or `'` are now displayed as HTML entities in the page instead of as raw markup. Legitimate values like `Order #123 & Associates` render as `Order #123 &amp; Associates`, which displays correctly to the user.
- Script tags, event handlers, and other HTML/JavaScript constructs in query parameters are neutralized and displayed as plain text.
- No change to the HTTP response content type, status code, or overall page structure.
