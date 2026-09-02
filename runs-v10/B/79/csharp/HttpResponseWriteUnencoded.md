## Verdict

Confirmed vulnerability. Untrusted query-string data flows directly to `Response.Write()` without encoding, enabling XSS.

## Source

Line 11: `string ticketRef = Request.QueryString["ticketRef"];`

Taint source: HTTP query parameter from user input, treated as untrusted.

## Fix

**Vulnerable code (line 18):**
```csharp
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");
```

**Fixed code:**
```csharp
Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");
```

## Explanation

The vulnerability arises because `ticketRef` is read directly from `Request.QueryString` and concatenated into HTML markup without encoding. An attacker can craft a malicious query string like `?ticketRef=<script>alert('XSS')</script>` to inject arbitrary JavaScript into the page.

The fix applies `HttpUtility.HtmlEncode()` to encode special HTML characters (`<`, `>`, `&`, `"`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`). This converts the malicious input into safe text content that the browser renders as visible text rather than executable code. The fix is applied at the output sink (the `Response.Write()` call) in the HTML body context where the data appears.

## Behaviour changes

**Before:** A query parameter `?ticketRef=<img src=x onerror="alert('XSS')">` executes JavaScript.

**After:** The same input is rendered as literal text: `Showing status for ticket: &lt;img src=x onerror="alert('XSS')"&gt;`, visible to the user but not executed.

**Legitimate content:** A ticket reference containing `<` or `>` characters (e.g., "TICKET-<ABC>") is safely encoded as `TICKET-&lt;ABC&gt;` and displays correctly.
