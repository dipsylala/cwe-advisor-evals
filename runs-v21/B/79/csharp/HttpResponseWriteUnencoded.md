## Verdict

Confirmed XSS vulnerability via unencoded output of untrusted query parameter into HTML response body.

## Source

`Request.QueryString["ticketRef"]` (line 11) - untrusted user-supplied query parameter flows directly to output sink without validation or encoding.

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

            // Fixed: ticketRef is now HTML-encoded before inclusion in response
            Response.Write("<p>Showing status for ticket: " + HttpUtility.HtmlEncode(ticketRef) + "</p>");

            Response.Write("</body></html>");
        }
    }
}
```

## Explanation

The vulnerability occurs because `ticketRef` is directly concatenated into an HTML string without encoding, allowing an attacker to inject arbitrary HTML and JavaScript. The fix applies `HttpUtility.HtmlEncode()` to encode the untrusted value, converting special characters (`<`, `>`, `&`, `"`, `'`) to HTML entities. This ensures the value is treated as data, not executable code, while preserving the intended text display. `HttpUtility.HtmlEncode()` is the standard encoding mechanism in classic ASP.NET Web Forms (System.Web) for HTML body context and is appropriate for this vulnerability sink.

## Behaviour changes

- Special characters in `ticketRef` will be encoded as HTML entities (e.g., `<` becomes `&lt;`, `>` becomes `&gt;`)
- Legitimate ticket references containing these characters will render correctly as their encoded forms
- Malicious script injection attempts will render as literal text, preventing code execution
- No functional change to legitimate uses; injection attacks are neutralized
