## Verdict

Exploitable. Untrusted query string parameter `ticketRef` flows directly into `Response.Write()` HTML output without encoding, allowing attackers to inject malicious scripts.

## Source

**Entry point**: `Request.QueryString["ticketRef"]` (line 11) - untrusted user input from URL query parameters

**Data flow**: QueryString parameter → direct string concatenation → Response.Write() at line 18

**Sink**: `Response.Write()` at line 18 - outputs HTML without encoding

## Fix

**Vulnerable code:**
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

            // VULNERABLE: ticketRef is not encoded before writing to HTML
            Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");

            Response.Write("</body></html>");
        }
    }
}
```

**Fixed code:**
```csharp
using System;
using System.Net;
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

            // FIXED: ticketRef is HTML-encoded before writing
            Response.Write("<p>Showing status for ticket: " + WebUtility.HtmlEncode(ticketRef) + "</p>");

            Response.Write("</body></html>");
        }
    }
}
```

## Explanation

The fix applies HTML encoding to the untrusted `ticketRef` parameter using `System.Net.WebUtility.HtmlEncode()` before writing it to the response. This is the recommended approach for Web Forms (System.Web), as stated in the CWE-79 C# guidance. HTML encoding converts dangerous characters (`<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`) into HTML entities, preventing the browser from interpreting user input as markup or script. The attacker cannot break out of the HTML text context to inject script tags or event handlers. Only the import statement and the encoding call were added; no other behavior changed.

## Behaviour changes

None. The fix preserves the original behavior: the response still contains the ticket reference in a paragraph element. Legitimate content containing special characters (e.g., `<ticket#123>` or `AT&T`) will render correctly as text, not as markup.
