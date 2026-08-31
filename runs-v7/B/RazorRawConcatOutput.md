## Verdict

Exploitable. Untrusted query parameters `orderId` and `customerNote` are concatenated directly into an HTML string without any encoding and rendered to the response at line 20, allowing XSS payload injection.

## Source

`Request.Query["orderId"]` (line 10) and `Request.Query["note"]` (line 11) are untrusted user inputs from query parameters, treated as data sources.

## Fix

**Vulnerable code:**
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

**Fixed code:**
```csharp
using System.Text.Encodings.Web;

string orderId = Request.Query["orderId"];
string customerNote = Request.Query["note"];

string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + HtmlEncoder.Default.Encode(orderId) + "</p>" +
    "<p>Note from customer: " + HtmlEncoder.Default.Encode(customerNote) + "</p>" +
    "</body></html>";

return Content(html, "text/html");
```

## Explanation

The untrusted query parameters are directly interpolated into an HTML string without encoding, then rendered as HTML via `Content()`. An attacker can inject malicious scripts (e.g., `?orderId=<script>alert('xss')</script>`) that execute in victim browsers. The fix applies `HtmlEncoder.Default.Encode()` to both `orderId` and `customerNote` before concatenation. This encodes HTML special characters (`<`, `>`, `&`, quotes) so they render as literal text rather than executable markup, eliminating the XSS sink while preserving legitimate content.

## Behaviour changes

None. The encoding preserves the data semantics and display of legitimate customer notes containing characters like `<` or `&` while preventing script injection. The `Content()` method's return type and contract are unchanged.
