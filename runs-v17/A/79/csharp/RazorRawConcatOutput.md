## Verdict

The code is vulnerable to reflected cross-site scripting (XSS). Untrusted query parameters `orderId` and `customerNote` are concatenated directly into an HTML string and returned without encoding, allowing an attacker to inject arbitrary HTML and JavaScript.

## Source

```csharp
string orderId = Request.Query["orderId"];
string customerNote = Request.Query["note"];

string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + orderId + "</p>" +
    "<p>Note from customer: " + customerNote + "</p>" +
    "</body></html>";

return Content(html, "text/html");
```

An attacker can craft a malicious URL such as `?orderId=<script>alert('xss')</script>` to inject and execute arbitrary code in the victim's browser.

## Fix

### File: RazorRawConcatOutput.cs

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

The fix uses `System.Net.WebUtility.HtmlEncode()` to encode both untrusted query parameters before inserting them into the HTML string. This method converts special HTML characters to their entity equivalents:
- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `&` becomes `&amp;`
- `"` becomes `&quot;`
- `'` becomes `&#x27;`

This prevents the browser from interpreting user input as HTML or JavaScript code. When a malicious payload like `<script>alert('xss')</script>` is encoded, it is displayed as literal text in the page rather than executed.

The fix adds `using System.Net;` to access the `WebUtility` class, which is part of the standard .NET Framework and requires no additional dependencies.
