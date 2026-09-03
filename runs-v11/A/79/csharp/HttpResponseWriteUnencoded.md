## Verdict

Confirmed. Line 18 concatenates an unencoded query parameter into HTML output, allowing arbitrary JavaScript execution through the `ticketRef` parameter.

## Source

```csharp
string ticketRef = Request.QueryString["ticketRef"];

Response.ContentType = "text/html";
Response.Write("<html><body>");
Response.Write("<h2>Support Ticket Lookup</h2>");

Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");

Response.Write("</body></html>");
```

An attacker can craft a URL like `?ticketRef=<script>alert('XSS')</script>` to execute arbitrary JavaScript in the victim's browser.

## Fix

```csharp
string ticketRef = Request.QueryString["ticketRef"];

Response.ContentType = "text/html";
Response.Write("<html><body>");
Response.Write("<h2>Support Ticket Lookup</h2>");

Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");

Response.Write("</body></html>");
```

Wrap the user-supplied `ticketRef` with `HttpUtility.HtmlEncode()` before concatenating it into HTML content.

## Explanation

`HttpUtility.HtmlEncode()` converts special HTML characters (`<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`, `'` → `&#39;`) so that input is rendered as literal text rather than interpreted as markup or script. This prevents the query parameter from breaking out of its context and injecting HTML or JavaScript. The `System.Web` namespace is already imported, making `HttpUtility` available without additional references.
