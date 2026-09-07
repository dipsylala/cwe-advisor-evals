## Verdict
XSS vulnerability confirmed. Untrusted user input from query parameters is concatenated directly into HTML without encoding, allowing injected scripts to execute in the victim's browser.

## Source
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

## Fix
Import `System.Text.Encodings.Web` and apply `HtmlEncoder.Default.Encode()` to both `orderId` and `customerNote` before concatenating them into the HTML string. This converts special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents, preventing the browser from interpreting user input as markup or script tags.

The fixed lines are:
```
"<p>Order: " + HtmlEncoder.Default.Encode(orderId) + "</p>" +
"<p>Note from customer: " + HtmlEncoder.Default.Encode(customerNote) + "</p>" +
```

## Explanation
ASP.NET Core's `HtmlEncoder.Default.Encode()` is the standard defense against HTML injection in dynamically constructed content. It converts dangerous characters into harmless HTML entities: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and quotes become `&#x27;` or `&quot;`. This ensures that even if an attacker supplies input like `<script>alert('xss')</script>`, it will be rendered as literal text in the HTML rather than executed as a script tag. The encoding is transparent to the user—the displayed text remains readable while the injection vector is closed.
