## Verdict

Confirmed. The request's `q` query-string value is concatenated directly into a single-quoted
JavaScript string literal inside an inline `<script>` block, then written to the response with no
encoding. An attacker-supplied value such as `q='; alert(document.cookie); var x='` (or a value
containing `</script><script>...`) breaks out of the string literal and executes arbitrary
JavaScript in the victim's browser — reflected XSS in a JS-string execution context.

## Source

`Request.QueryString["q"]` read into `searchTerm` at line 14 (`JsContextUnencodedOutput.cs`).
This is raw, attacker-controlled request data with no validation or encoding applied before use.

## Fix

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

            // Encode for the JavaScript string-literal context before embedding.
            string encodedSearchTerm = HttpUtility.JavaScriptStringEncode(searchTerm);

            string script =
                "<script>" +
                "var lastSearch = '" + encodedSearchTerm + "';" +
                "trackSearch(lastSearch);" +
                "</script>";

            Response.Write(script);
        }
    }
}
```

## Explanation

The sink (`Response.Write(script)` at line 23) writes a string into a live `<script>` block, and
the value entering that string was built by naive concatenation of untrusted input — no encoding
appropriate to the JavaScript-string-literal context was applied between source and sink. Because
the payload lands inside a single-quoted JS string, HTML encoding alone would not neutralize it
(a raw `'` and `\` are meaningful in JavaScript but not HTML), so the fix must use a JavaScript-
aware encoder specifically.

`HttpUtility.JavaScriptStringEncode` escapes characters that are significant inside a JS string
literal — `'`, `"`, `\`, newlines, and other control characters — turning any attacker-supplied
quote or backslash into its escaped equivalent so it can no longer terminate the string or inject
new statements. It also neutralizes `</script>` sequences is not automatic, but because the value
is confined to a quoted string rather than raw markup, and the escaped output contains no literal
`<` or `>` transformation by default, applying the encoder without allowing embedded `<script>`
closing sequences to pass through unescaped removes the injection vector for this case; if the
input could still contain a literal `</script>` substring after JS-escaping, additionally encoding
or stripping the forward slash sequence (or, better, moving the value out of inline markup
entirely) closes that residual path.

The most robust long-term fix is architectural rather than incremental: avoid building executable
script via string concatenation at all. Emit the search term into a non-executable location, such
as a `data-*` attribute on an HTML element, HTML-encoded via `HttpUtility.HtmlEncode`, and have the
static, already-loaded client script read that attribute at runtime instead of receiving
interpolated values inside a freshly generated `<script>` block. That removes the need to reason
about JS-string escaping correctness altogether and is preferable wherever the page's structure
allows it.
