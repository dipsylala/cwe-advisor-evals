## Verdict

Exploitable.

## Source

`Request.Query["orderId"]` and `Request.Query["note"]` at lines 10-11. Both are attacker-controlled query parameters with no validation.

## Fix

Vulnerable code (lines 13-20):

```csharp
string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + orderId + "</p>" +
    "<p>Note from customer: " + customerNote + "</p>" +
    "</body></html>";

// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
return Content(html, "text/html");
```

Fixed code:

```csharp
using System.Text.Encodings.Web;

// ... in the controller method ...

string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + HtmlEncoder.Default.Encode(orderId) + "</p>" +
    "<p>Note from customer: " + HtmlEncoder.Default.Encode(customerNote) + "</p>" +
    "</body></html>";

return Content(html, "text/html");
```

## Explanation

The vulnerability exists because untrusted query parameter values are concatenated directly into HTML content and sent to the browser without encoding. An attacker can inject malicious scripts by including payloads like `<script>alert('xss')</script>` or `"><img src=x onerror="alert('xss')"/>` in the query parameters, which will execute in the victim's browser.

The fix applies HTML encoding using `HtmlEncoder.Default.Encode()` from the built-in `System.Text.Encodings.Web` namespace. This encodes HTML special characters (`<`, `>`, `&`, `"`, `'`) into their entity representations, preventing the injected content from being interpreted as executable code. The encoded values remain visible as legitimate text to the user while being neutralized as attack vectors.

## Behaviour changes

The output will escape HTML special characters in the order ID and customer note. For example, if `orderId` contains `<script>`, it will be displayed as `&lt;script&gt;` in the HTML response. This is the intended behaviour and necessary to eliminate the XSS vulnerability. Legitimate content containing special characters (such as mathematical symbols using `<`, `>`, or ampersands in company names) will render correctly as their HTML entity equivalents.

No other behaviour changes: the response structure, content type (`text/html`), and return type remain identical.
