## Verdict

Exploitable. The `ticketRef` parameter from user input (via `Request.QueryString`) flows directly into `Response.Write()` without encoding, allowing arbitrary HTML or JavaScript injection.

## Source

`Request.QueryString["ticketRef"]` (line 11) — untrusted user input from the query string, treated as a string without validation or transformation.

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

            // Fixed: Apply HtmlEncode to neutralize any HTML/script tags in the input
            Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");

            Response.Write("</body></html>");
        }
    }
}
```

## Explanation

The vulnerability occurs because `Response.Write()` outputs its argument directly to the HTML response body without escaping. An attacker can supply input like `ticketRef=<script>alert(1)</script>` or `ticketRef=" onload="alert(1)`, which executes in the victim's browser. The fix applies `HttpUtility.HtmlEncode()` to the untrusted input before including it in the output. This encodes HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), so user input is rendered as data rather than executable code. `HttpUtility.HtmlEncode()` is available in the already-imported `System.Web` namespace and is Microsoft's recommended encoding method for Web Forms.

## Behaviour changes

None. The output format and sink contract remain identical. Legitimate content containing `<`, `>`, or `&` characters renders correctly as HTML entities, and the page functionality is preserved. The only change is that the page no longer renders raw HTML or script tags supplied by the user.
