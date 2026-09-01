## Verdict

Confirmed XSS vulnerability. Untrusted user input from query string is concatenated directly into HTML output without encoding, allowing arbitrary script injection.

## Source

`Request.QueryString["ticketRef"]` at line 11 — untrusted input from HTTP query parameter.

## Fix

Replace line 18:

**Before:**
```csharp
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");
```

**After:**
```csharp
Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");
```

## Explanation

`HttpUtility.HtmlEncode()` encodes the query parameter value before it reaches the HTML sink, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) to HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures the value is treated as data, not markup, preventing script injection while preserving the displayed text for legitimate values. The encoding is applied in the HTML body context, which is the correct context for this sink.

## Behaviour changes

- Payloads like `<img src=x onerror=alert('XSS')>` are now rendered as literal text: `&lt;img src=x onerror=alert('XSS')&gt;`
- Legitimate input containing `<`, `>`, or `&` is still displayed as entered (encoded for browser display)
- No functional behaviour change to valid ticket references
