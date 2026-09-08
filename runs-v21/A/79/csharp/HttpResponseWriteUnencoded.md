## Verdict
VULNERABLE

## Source
User-supplied input from `Request.QueryString["ticketRef"]` is concatenated directly into HTML output without encoding.

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

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");

            Response.Write("</body></html>");
        }
    }
}
```

## Explanation
The vulnerability on line 18 concatenates the user-supplied `ticketRef` query parameter directly into the HTML output without encoding. An attacker can inject malicious JavaScript by providing input like `ticketRef=<script>alert('XSS')</script>`, which will execute in the victim's browser.

The fix applies `HttpUtility.HtmlEncode()` to the untrusted input before writing it to the response. This method escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) into their entity representations (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing script injection. The `HttpUtility` class is available from the `System.Web` namespace already imported at the top of the file.
