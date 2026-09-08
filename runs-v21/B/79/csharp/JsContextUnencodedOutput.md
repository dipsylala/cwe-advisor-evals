## Verdict

Exploitable. Untrusted user input from the query string is concatenated directly into a JavaScript string literal without encoding, allowing an attacker to break out of the string context and inject arbitrary JavaScript code.

## Source

`Request.QueryString["q"]` at line 14. Query string parameters are untrusted attacker-controlled input.

## Fix

### File: JsContextUnencodedOutput.cs

```csharp
using System;
using System.Web;
using System.Web.UI;
using System.Text.Encodings.Web;

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
            
            // Encode the search term for safe inclusion in a JavaScript string literal.
            string encodedSearchTerm = JavaScriptEncoder.Default.Encode(searchTerm);

            string script =
                "<script>" +
                "var lastSearch = '" + encodedSearchTerm + "';" +
                "trackSearch(lastSearch);" +
                "</script>";

            // Safe to write: the value is now JavaScript-encoded.
            Response.Write(script);
        }
    }
}
```

## Explanation

The vulnerability occurs because untrusted user input is placed directly into a JavaScript string literal without encoding. If an attacker supplies `q='; alert('XSS'); var x='`, the output becomes `var lastSearch = ''; alert('XSS'); var x='';`, which executes the injected alert. HTML encoding (e.g., `WebUtility.HtmlEncode()`) does not protect here because the browser's HTML parser never decodes entities inside `<script>` blocks—the value reaches the JavaScript interpreter as the literal string `&quot;`, not as a quote character. The fix uses `JavaScriptEncoder.Default.Encode()` from `System.Text.Encodings.Web`, which escapes characters that have special meaning in JavaScript string contexts (single quotes, backslashes, line terminators, and control characters). This ensures the value remains a string literal regardless of its content. The encoder is part of the .NET standard library and requires no additional dependencies.

## Behaviour changes

None. The encoder preserves the string value semantically—only dangerous characters are escaped. The call to `trackSearch(lastSearch)` receives the same data, just with metacharacters neutralized, so the application behaviour is unchanged. The `Response.Write()` sink contract (writing to the HTTP response body) is preserved.

