## Verdict

Exploitable

## Source

User-supplied query string parameters `orderId` and `note` read at lines 10-11 via `Request.Query` are concatenated directly into an HTML string at lines 15-16 and rendered without encoding at line 20 via `Content(html, "text/html")`.

- `orderId`: `Request.Query["orderId"]` (line 10)
- `customerNote`: `Request.Query["note"]` (line 11)

## Fix

**Vulnerable code (lines 1-24):**

```csharp
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
                "<p>Order: " + orderId + "</p>" +  // Unencoded user input
                "<p>Note from customer: " + customerNote + "</p>" +  // Unencoded user input
                "</body></html>";

            return Content(html, "text/html");
        }
    }
}
```

**Fixed code:**

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

The vulnerability arises because untrusted user input from query parameters is concatenated directly into HTML markup and returned to the browser without any encoding. An attacker can inject malicious scripts or HTML by providing values like `orderId=<script>alert('xss')</script>` or `note=<img src=x onerror=alert('xss')>`. The browser interprets these as active HTML/JavaScript and executes them in the victim's session.

The fix applies `HtmlEncoder.Default.Encode()` from `System.Text.Encodings.Web` to both user inputs before they are embedded in the HTML string. This encodes dangerous characters (`<`, `>`, `&`, quotes) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), rendering them inert. The encoded values remain safe display values while preventing script execution. This is the recommended pattern for explicit HTML encoding in ASP.NET Core controllers when hand-building HTML responses.

## Behaviour changes

None. `HtmlEncoder.Default.Encode()` transforms the input by escaping HTML metacharacters, which are rendered as escaped entities by the browser, producing the same visual output for legitimate content (e.g., order IDs containing `&` or `<` are displayed correctly as entities). The `Content()` method's return type, content-type header, and error behaviour remain unchanged.

