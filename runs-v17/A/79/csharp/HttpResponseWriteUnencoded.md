## Verdict
Confirmed vulnerability. Line 18 concatenates untrusted user input directly into HTML output without encoding.

## Source
Line 18 reads the untrusted `ticketRef` parameter from `Request.QueryString` and concatenates it directly into an HTML response body via `Response.Write()`. The value passes through without any encoding or sanitization, allowing an attacker to inject arbitrary HTML or JavaScript by crafting a malicious query string.

## Fix
### File: HttpResponseWriteUnencoded.cs
```csharp
using System;
using System.Web;
using System.Web.UI;

namespace EvalCases.WebForms
{
    public class FeedbackStatusHandler : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string ticketRef = Request.QueryString["ticketRef"];

            Response.ContentType = "text/html";
            Response.Write("<html><body>");
            Response.Write("<h2>Support Ticket Lookup</h2>");

            // Fixed: HTML-encode the user input before writing to response
            Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");

            Response.Write("</body></html>");
        }
    }
}
```

## Explanation
CWE-79 (Cross-site Scripting) arises when untrusted input reaches an HTML output sink without encoding. The `ticketRef` parameter originates from user-controlled input and can contain script payloads like `<script>alert('XSS')</script>`. `HttpUtility.HtmlEncode()` converts special HTML characters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), ensuring the browser treats the input as text rather than executable code. This is the standard output-encoding defense for ASP.NET when rendering user data in HTML contexts.
