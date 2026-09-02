## Verdict

The finding is valid. Untrusted query parameters (`orderId` and `customerNote`) are concatenated directly into an HTML string and rendered without encoding, enabling XSS injection.

## Source

`Request.Query["orderId"]` and `Request.Query["note"]` at lines 10-11. These are untrusted because they derive directly from user-supplied query parameters.

## Fix

Replace the string concatenation with output encoding. Use `System.Text.Encodings.Web.HtmlEncoder.Default.Encode()` to encode untrusted values before placing them into HTML:

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

The fix applies HTML encoding to each untrusted value at the sink before it reaches the browser. `HtmlEncoder.Default.Encode()` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), ensuring they are rendered as text rather than interpreted as HTML markup or event handlers. The encoded values remain safe when concatenated into an HTML body context.

An attacker's attempt to inject `<img src=x onerror="alert('XSS')">` will be encoded to `&lt;img src=x onerror=&quot;alert(&#x27;XSS&#x27;)&quot;&gt;` and display as literal text in the browser, not execute JavaScript.

## Behaviour changes

The fix changes how user-supplied content containing HTML metacharacters is displayed. Legitimate content like "Order <#123>" or quotes in notes is now rendered as text rather than parsed as markup, which is the correct behaviour. Any malicious payload attempting HTML/JavaScript injection is neutralized to text display. No functional change to the application's intended behaviour occurs; legitimate content continues to display correctly.
