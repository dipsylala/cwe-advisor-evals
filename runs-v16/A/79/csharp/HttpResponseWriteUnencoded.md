## Verdict

This is a confirmed CWE-79 (Cross-site Scripting) vulnerability. User-controlled input from `Request.QueryString["ticketRef"]` is written directly to the HTTP response without HTML encoding, allowing arbitrary JavaScript injection.

## Source

Line 11 retrieves untrusted input:
```
string ticketRef = Request.QueryString["ticketRef"];
```

Line 18 writes it to the response without encoding:
```
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");
```

An attacker can craft a request with `ticketRef=<script>alert('XSS')</script>` or similar payloads to execute arbitrary JavaScript in the victim's browser.

## Fix

HTML-encode the user input before writing it to the response:

```csharp
Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");
```

Alternatively, use `Server.HtmlEncode()`:

```csharp
Response.Write("<p>Showing status for ticket: " + Server.HtmlEncode(ticketRef) + "</p>");
```

## Explanation

`HttpUtility.HtmlEncode()` and `Server.HtmlEncode()` convert special HTML characters (`<`, `>`, `&`, `"`, `'`) to their corresponding HTML entity references. This prevents the browser from interpreting user input as markup or script code.

When the attacker's input contains `<script>`, it becomes `&lt;script&gt;` and renders as literal text rather than an executable script tag. This is the standard and necessary defence against reflected XSS in ASP.NET.

Apply the encoding at the point where untrusted data enters the HTML context — before `Response.Write()` — to ensure the vulnerability is closed.
