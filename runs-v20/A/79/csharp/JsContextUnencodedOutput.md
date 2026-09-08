## Verdict

Confirmed. `Page_Load` reads the raw `q` query-string parameter and concatenates it directly into a string literal inside an inline `<script>` block, which is then written to the response with `Response.Write`. An attacker-controlled value such as `';alert(document.cookie);//` breaks out of the single-quoted JavaScript string and executes arbitrary script in the victim's browser (reflected XSS in a JavaScript context).

## Source

`Request.QueryString["q"]` (line 14) — untrusted, attacker-controlled input taken verbatim from the request URL and never validated or encoded before use.

## Fix

### File: JsContextUnencodedOutput.cs

```csharp
using System;
using System.Web;
using System.Web.UI;

namespace EvalCases
{
    // ASP.NET Web Forms page that echoes the last search term back into an
    // inline script block so a client-side analytics helper can log it.
    public partial class SearchResultsPage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Untrusted input: raw query string value from the request.
            string searchTerm = Request.QueryString["q"];

            // Encode for a JavaScript string-literal context: JavaScriptStringEncode
            // escapes quotes, backslashes, and control characters so the value cannot
            // terminate the ' ... ' literal early. It does not escape '/', so also
            // neutralize any "</script>" sequence the value might contain, which would
            // otherwise let the HTML parser close the script block before the escaped
            // JS string is ever evaluated.
            string safeSearchTerm = HttpUtility.JavaScriptStringEncode(searchTerm)
                .Replace("/", "\\/");

            string script =
                "<script>" +
                "var lastSearch = '" + safeSearchTerm + "';" +
                "trackSearch(lastSearch);" +
                "</script>";

            Response.Write(script);
        }
    }
}
```

## Explanation

The output sink is a JavaScript string literal, not HTML, so the correct neutralization is JavaScript string encoding rather than HTML encoding: `HttpUtility.JavaScriptStringEncode` escapes the single quote, backslash, and control characters (`\n`, `\r`, etc.) that would otherwise let attacker input terminate the `'...'` literal and inject new script statements.

`JavaScriptStringEncode` does not escape `/`, so a value containing the literal substring `</script>` would still close the surrounding `<script>` tag at the HTML-parsing stage, before the browser ever gets to interpret the JavaScript — this happens regardless of how well the JS-string escaping itself is done, because the HTML tokenizer looks for that closing tag as raw text. Replacing `/` with `\/` breaks up any `</script>` sequence in the input while remaining valid, semantically identical JavaScript (an escaped forward slash in a JS string literal is just a forward slash), closing that bypass.

The fix preserves the existing inline-script architecture and the `trackSearch` call contract — only the untrusted value is transformed before concatenation, so no unrelated behavior changes.
