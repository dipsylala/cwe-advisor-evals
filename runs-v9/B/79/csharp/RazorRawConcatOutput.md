## Verdict

exploitable (confidence: high)

## Source

- `Request.Query["orderId"]` (line 10)
- `Request.Query["note"]` (line 11)

Both are attacker-controlled query-string values with no validation or encoding applied before use.

## Fix

Vulnerable code:

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
                "<p>Order: " + orderId + "</p>" +
                "<p>Note from customer: " + customerNote + "</p>" +
                "</body></html>";

            // SAST FINDING: CWE-79 reported here. Sink is the next statement.
            return Content(html, "text/html");
        }
    }
}
```

Fixed code:

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

`Confirm()` builds its response as a raw HTML string via plain string concatenation and returns it through `Content(html, "text/html")`, which writes the string to the response body verbatim - this action method is a controller, not a `.cshtml` view, so Razor's automatic `@variable` encoding never applies here. Both `orderId` and `customerNote` come straight from the query string and are spliced into that HTML with no encoding, so a request such as `?note=<script>...</script>` renders and executes in the victim's browser exactly as submitted. The fix wraps both values in `System.Net.WebUtility.HtmlEncode()` at the point of concatenation, which is the sink for this hand-built markup outside of Razor. Encoding converts `<`, `>`, `&`, and quote characters into their HTML entity equivalents, so any markup or script the attacker supplies is rendered as inert display text inside the `<p>` elements rather than parsed as HTML/script by the browser, closing the injection while leaving legitimate order IDs and notes (including ones containing `&`, `<` as literal display characters) still readable.

## Behaviour changes

None beyond the encoding itself, which is the fix: `orderId` and `customerNote` values containing `<`, `>`, `&`, `"`, or `'` will now appear in the rendered page as their escaped entity forms (e.g. `&lt;`) instead of being interpreted as HTML/script. The `Content(html, "text/html")` call, its return type, its content-type header, and the response status/failure behaviour are all unchanged.
