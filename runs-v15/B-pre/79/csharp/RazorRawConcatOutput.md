## Verdict

Exploitable. Untrusted query parameters `orderId` and `customerNote` flow into an HTML string without encoding, then are rendered to the response via `Content(html, "text/html")`, allowing JavaScript injection.

## Source

- `Request.Query["orderId"]` (line 10)
- `Request.Query["note"]` (line 11)

Both are untrusted user input from query parameters.

## Fix

**Vulnerable code (lines 10-20):**
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

// ... in method:
string orderId = Request.Query["orderId"];
string customerNote = Request.Query["note"];

string encodedOrderId = HtmlEncoder.Default.Encode(orderId);
string encodedCustomerNote = HtmlEncoder.Default.Encode(customerNote);

string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + encodedOrderId + "</p>" +
    "<p>Note from customer: " + encodedCustomerNote + "</p>" +
    "</body></html>";

return Content(html, "text/html");
```

## Explanation

The vulnerability arises because untrusted query parameters are concatenated directly into an HTML string without encoding. An attacker can inject JavaScript via payloads like `?orderId=<script>alert('XSS')</script>`, which will execute in victims' browsers when the HTML is rendered. The fix applies HTML encoding to both `orderId` and `customerNote` using `HtmlEncoder.Default.Encode()` from `System.Text.Encodings.Web` before including them in the HTML string. This encodes special characters (`<`, `>`, `&`, `"`, `'`) as HTML entities, ensuring the user input is treated as data rather than executable markup. The encoding is context-appropriate for HTML element content and prevents the injection of script tags or other malicious markup.

## Behaviour changes

None. `HtmlEncoder.Default.Encode()` produces a string with special characters escaped, which is then concatenated into the HTML string exactly as the original code concatenated the raw input. The `Content()` method still receives a valid HTML string and renders it as before, but now with malicious markup neutralized. Legitimate content containing `<`, `&`, and quotes will render correctly as HTML entities: `<` becomes `&lt;`, preserving readability while preventing interpretation as markup.
