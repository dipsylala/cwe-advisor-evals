## Verdict
Confirmed: CWE-79 (Cross-site Scripting) via unencoded query parameter in HTTP response output.

## Source
Line 18 writes an unencoded query string parameter `ticketRef` to the HTML response. The value flows from `Request.QueryString["ticketRef"]` (line 11) without encoding and is concatenated directly into the HTML sent to `Response.Write()` (line 18).

## Fix
Replace line 18 with:
```csharp
Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");
```

## Explanation
An attacker can inject JavaScript by appending `?ticketRef=<script>alert(1)</script>` to the URL. Without HTML encoding, the browser parses the injected tags as code. `HttpUtility.HtmlEncode()` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), rendering them harmless as literal text. This prevents script injection while preserving the user input for display.
