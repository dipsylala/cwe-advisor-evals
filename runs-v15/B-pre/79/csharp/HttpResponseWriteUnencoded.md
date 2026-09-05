## Verdict
Confirmed. The untrusted `ticketRef` value from `Request.QueryString` flows directly into HTML output via `Response.Write()` without encoding, enabling XSS injection in the HTML body context.

## Source
`Request.QueryString["ticketRef"]` (line 11) - attacker-controlled query string parameter passed directly to the sink without validation or transformation.

## Fix
Replace line 18:
```csharp
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");
```

With:
```csharp
Response.Write("<p>Showing status for ticket: " + System.Web.HttpUtility.HtmlEncode(ticketRef) + "</p>");
```

Alternatively, use `System.Net.WebUtility.HtmlEncode()` if System.Web is unavailable.

## Explanation
`HttpUtility.HtmlEncode()` escapes HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This converts any injected markup or script tags into literal text that the browser renders as content rather than executable code. The encoding is applied at the output sink (where data enters HTML body context), ensuring the value remains data regardless of how it was stored or processed earlier. The fix preserves the existing output contract—`Response.Write()` still outputs a string to the response—and only changes what the string contains.

## Behaviour changes
- **Output format**: Attackers' angle brackets and quotes now appear HTML-encoded in the response, rendering as visible text rather than executable markup.
- **Legitimate content**: Values containing `<`, `&`, or quotes (e.g., `"Project A & B" < deadline`) now render correctly as escaped sequences, preserving semantic meaning while preventing injection.
- **No functional regression**: The page layout, styling, and logic remain unchanged; only the rendering of user-supplied content is now safe.
