## Verdict

Confirmed. The untrusted `searchTerm` from the query string is concatenated directly into JavaScript code without encoding, enabling script injection.

## Source

Line 18 in the script string construction concatenates `searchTerm` directly without encoding. When an attacker supplies `q='; alert('xss'); //` in the query string, the resulting JavaScript becomes:

```
var lastSearch = ''; alert('xss'); //'
```

This executes the attacker's code in the victim's browser.

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

            string script =
                "<script>" +
                "var lastSearch = '" + HttpUtility.JavaScriptStringEncode(searchTerm) + "';" +
                "trackSearch(lastSearch);" +
                "</script>";

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            Response.Write(script);
        }
    }
}
```

## Explanation

The fix applies `HttpUtility.JavaScriptStringEncode()` to `searchTerm` before embedding it in the JavaScript string literal. This encoder escapes characters that have special meaning in JavaScript strings (quotes, backslashes, line terminators like U+2028/U+2029, and dangerous characters like `<`), converting them to safe escape sequences. For example, a single quote becomes `\'`, preventing the attacker from breaking out of the string context. `HttpUtility.JavaScriptStringEncode()` is the standard choice for Web Forms applications (System.Web) encoding values that will appear in script source code.
