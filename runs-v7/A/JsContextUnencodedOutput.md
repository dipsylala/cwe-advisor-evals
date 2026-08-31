## Verdict
Vulnerable to JavaScript context injection.

## Source
`searchTerm` is sourced from untrusted input: `Request.QueryString["q"]` (line 14).

## Fix
Apply context-aware encoding before embedding the user input into a JavaScript string literal:

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
            string searchTerm = Request.QueryString["q"];

            // Encode the input for safe use within a JavaScript string literal
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
The code concatenates an unencoded query string value into a JavaScript string literal within an HTML script block. An attacker can inject JavaScript by closing the string with a quote and adding arbitrary code: `q='; alert(document.cookie); //` would result in executable code.

`HttpUtility.JavaScriptStringEncode()` escapes characters that have special meaning in JavaScript string contexts (single quotes, double quotes, backslashes, newlines, etc.), ensuring the user input cannot break out of the string literal. This is the appropriate encoding for embedding untrusted data into JavaScript string literals in ASP.NET.
