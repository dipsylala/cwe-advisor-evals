## Verdict

Confirmed. `searchTerm` is untrusted (raw `Request.QueryString["q"]`) and is concatenated directly into a single-quoted JavaScript string literal that is then written into the response as an inline `<script>` block. An attacker can close the string and inject arbitrary script, e.g. `q=x';alert(document.cookie);//` produces `var lastSearch = 'x';alert(document.cookie);//';trackSearch(lastSearch);`, which executes.

## Source

`string searchTerm = Request.QueryString["q"];` (line 14) — attacker-controlled query string value, flows unmodified into the JavaScript string literal built at lines 16-20 and written to the response at line 23 (`Response.Write(script)`).

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

            string script =
                "<script>" +
                "var lastSearch = '" + HttpUtility.JavaScriptStringEncode(searchTerm) + "';" +
                "trackSearch(lastSearch);" +
                "</script>";

            Response.Write(script);
        }
    }
}
```

## Explanation

The value is being embedded into a JavaScript string-literal context inside an HTML page, not an HTML-attribute or HTML-body context, so HTML entity encoding (`HttpUtility.HtmlEncode`) would not neutralize this — it does not escape the quote and backslash characters that matter inside a JS string literal, and a payload like `'-alert(1)-'` needs no HTML metacharacters at all to break out.

`HttpUtility.JavaScriptStringEncode` (from `System.Web`) is the framework-native encoder built for exactly this context: it escapes the single quote delimiting the literal, double quotes, backslashes, and line terminators/control characters, and JSON-escapes non-ASCII where relevant, so the attacker-controlled value can no longer terminate the string or inject additional statements. It is applied to `searchTerm` at the point it is concatenated into the literal (line 18), which is the only place the untrusted value crosses into the script content — the surrounding literal quotes and script tags are static and don't need re-escaping.

This keeps the existing "log the raw search term via `trackSearch`" behavior intact — the decoded string value received by `trackSearch` is unchanged — while making it impossible for the input to be interpreted as JavaScript syntax rather than data. Verify by requesting the page with `q` values such as `');alert(1);//`, `\'-alert(1)-\'`, and a plain apostrophe, and confirming the rendered `<script>` block contains only backslash-escaped sequences inside the string literal and no injected statement executes.
