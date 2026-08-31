## Verdict

Confirmed: Line 18 writes user-supplied input directly to the HTTP response without HTML encoding, permitting arbitrary JavaScript execution in the browser.

## Source

The `ticketRef` parameter is obtained from the query string without validation:

```csharp
string ticketRef = Request.QueryString["ticketRef"];
```

Query string parameters are attacker-controlled and can contain arbitrary content.

## Fix

HTML-encode the user input before writing it to the response:

```csharp
Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");
```

Alternatively, use `System.Net.WebUtility.HtmlEncode(ticketRef)` if avoiding a direct System.Web dependency.

## Explanation

The vulnerability allows reflected XSS because `Response.Write()` outputs the HTML stream directly without escaping special characters. An attacker can craft a URL with a malicious payload in the `ticketRef` parameter (e.g., `?ticketRef=<img src=x onerror=alert('xss')>`), and the browser will interpret and execute the injected script in the victim's session.

HTML encoding converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their entity representations (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting user input as markup or script. The `HttpUtility.HtmlEncode()` method performs this transformation, rendering any malicious markup harmless while preserving readability for legitimate input.
