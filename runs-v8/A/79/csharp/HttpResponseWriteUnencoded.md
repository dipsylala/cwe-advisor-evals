## Verdict
Real XSS vulnerability. User-supplied `ticketRef` from query string is written to HTML response without encoding, allowing script injection.

## Source
Line 11: `string ticketRef = Request.QueryString["ticketRef"];` retrieves untrusted input.

## Fix
```csharp
Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");
```

## Explanation
The `ticketRef` parameter flows directly into HTML without encoding on line 18. `HttpUtility.HtmlEncode()` escapes special characters (`<`, `>`, `&`, `"`) so user input is treated as text content, not markup. This is the standard safe sink for writing untrusted strings into HTML context in ASP.NET.
