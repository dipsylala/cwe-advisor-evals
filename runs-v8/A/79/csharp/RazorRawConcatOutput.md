## Verdict

VULNERABLE. The code constructs an HTML string by concatenating unsanitized user input from query parameters directly into the output, creating an XSS vulnerability when the raw HTML is returned to the browser.

## Source

Lines 10–11 retrieve untrusted query parameters without validation:

```csharp
string orderId = Request.Query["orderId"];
string customerNote = Request.Query["note"];
```

These values flow directly into HTML construction on lines 15–16 via string concatenation with no encoding.

## Fix

HTML-encode the user-supplied values before inserting them into the HTML string. Import `System.Text.Encodings.Web` and use `HtmlEncoder.Default.Encode()`:

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

## Explanation

HTML encoding converts special characters to HTML entities (e.g., `<` becomes `&lt;`, `"` becomes `&quot;`), preventing the browser from interpreting user input as markup or script. `HtmlEncoder.Default.Encode()` is the built-in ASP.NET Core mechanism for this purpose and requires no external dependencies. By encoding both query parameters at lines 15–16, any injected script tags or event handlers are rendered as literal text rather than executable code.

