## Verdict

Exploitable. Untrusted user input from the query string is rendered directly into HTML output without encoding, allowing JavaScript injection.

## Source

`Request.QueryString["ticketRef"]` at line 11 - HTTP query parameter with no validation or encoding constraints.

## Fix

**Vulnerable code:**
```csharp
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");
```

**Fixed code:**
```csharp
Response.Write("<p>Showing status for ticket: " + System.Net.WebUtility.HtmlEncode(ticketRef) + "</p>");
```

## Explanation

The ticketRef value is concatenated directly into the HTML body text in a Response.Write() call. An attacker can craft a query string with HTML or JavaScript tags—for example, `?ticketRef=<script>alert('XSS')</script>`—and the browser will execute the injected script in the context of the application's domain. Applying HtmlEncode() escapes the HTML special characters (`<` becomes `&lt;`, `>` becomes `&gt;`, quotes become `&#34;` or `&#39;`), ensuring the value is treated as text data and not as markup or code. This closes the XSS sink while preserving the display of legitimate content that contains these characters.

## Behaviour changes

None. `System.Net.WebUtility.HtmlEncode()` escapes only HTML special characters and does not alter the logical function or return value of the code. Legitimate ticket references containing characters such as `<`, `>`, or `&` will display correctly with their encoded representations.
