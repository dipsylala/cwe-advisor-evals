## Verdict

**Confirmed CWE-79 (Cross-site Scripting).**  The untrusted `searchTerm` from `Request.QueryString["q"]` is embedded directly into a JavaScript string literal without encoding, allowing an attacker to break out of the string and inject arbitrary JavaScript code.

## Source

```csharp
using System;
using System.Web;
using System.Web.UI;

namespace EvalCases
{
    public partial class SearchResultsPage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Untrusted input: raw query string value from the request.
            string searchTerm = Request.QueryString["q"];

            string script =
                "<script>" +
                "var lastSearch = '" + searchTerm + "';" +
                "trackSearch(lastSearch);" +
                "</script>";

            // SAST FINDING: CWE-79 reported here.
            Response.Write(script);
        }
    }
}
```

The vulnerability is on line 23: `Response.Write(script)` writes unencoded content constructed from untrusted input.

## Fix

```csharp
using System;
using System.Web;
using System.Web.UI;

namespace EvalCases
{
    public partial class SearchResultsPage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Untrusted input: raw query string value from the request.
            string searchTerm = Request.QueryString["q"];

            // Encode the searchTerm for safe use in a JavaScript string literal
            string encodedSearchTerm = System.Web.HttpUtility.JavaScriptStringEncode(searchTerm);

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

The fix encodes the untrusted `searchTerm` using `System.Web.HttpUtility.JavaScriptStringEncode()` before embedding it into the JavaScript string. This method escapes special characters (quotes, backslashes, newlines, etc.) so the value cannot break out of the string literal or alter the JavaScript syntax.

For example, an attack payload like `' + alert('XSS') + '//` is transformed into a safe escaped form that is treated as a literal string value rather than executable code. The `JavaScriptStringEncode` method is the standard ASP.NET API for this context and handles all necessary escaping to prevent XSS in JavaScript string contexts.
