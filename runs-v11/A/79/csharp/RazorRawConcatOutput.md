## Verdict

The vulnerability is confirmed. User input from query parameters (`orderId` and `customerNote`) is concatenated directly into an HTML string without sanitization and returned as HTML, allowing arbitrary script injection.

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

Lines 10–11 read untrusted query parameter values. Lines 13–17 build an HTML string by concatenating these values directly without encoding. Line 20 returns this string as HTML (`text/html` MIME type), causing the browser to execute any embedded scripts.

An attacker can inject malicious JavaScript by passing `?orderId=<script>alert('xss')</script>` or similar payloads.

## Fix

Add using statement at the top:
```csharp
using System.Net;
```

Then encode the user inputs before concatenating:
```csharp
string orderId = Request.Query["orderId"];
string customerNote = Request.Query["note"];

string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + WebUtility.HtmlEncode(orderId) + "</p>" +
    "<p>Note from customer: " + WebUtility.HtmlEncode(customerNote) + "</p>" +
    "</body></html>";

return Content(html, "text/html");
```

## Explanation

`WebUtility.HtmlEncode()` converts special HTML characters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This prevents the browser from interpreting them as markup or script delimiters. When an attacker submits `<script>alert('xss')</script>`, it becomes `&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;`, which renders as plain text rather than executable code.

This is the primary defense against XSS when dynamically building HTML strings: encode all untrusted data before inserting it into HTML content.
