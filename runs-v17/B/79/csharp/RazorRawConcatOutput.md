## Verdict

exploitable

## Source

`Request.Query["orderId"]` and `Request.Query["note"]` - untrusted query string parameters from the HTTP request.

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

The original code concatenated untrusted query string parameters (`orderId` and `customerNote`) directly into an HTML string without any encoding. This allows an attacker to inject malicious HTML or JavaScript that will execute in victims' browsers. For example, passing `orderId=<script>alert('xss')</script>` would cause the script to execute.

The fix adds `using System.Text.Encodings.Web;` and wraps both untrusted values with `HtmlEncoder.Default.Encode()` before concatenation. This converts HTML special characters (`<`, `>`, `&`, `"`, `'`) into HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), ensuring they are rendered as text rather than interpreted as HTML tags or attributes. An attacker's injected payload will now appear as literal text in the output, eliminating the XSS vulnerability.

## Behaviour changes

None. The `HtmlEncoder.Default.Encode()` method takes a string and returns an encoded string. The method signature of `Content()` remains unchanged, and the response type (`text/html`) is unaffected. The only change is that special characters are escaped, which is the intended and necessary security fix.
