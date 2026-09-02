## Verdict
True Positive: CWE-79 XSS vulnerability in JavaScript context due to unencoded user input.

## Source
Line 14: `string searchTerm = Request.QueryString["q"];`

The `searchTerm` variable receives untrusted input directly from the query string without validation or encoding.

## Fix
Encode the user-controlled input using `HttpUtility.JavaScriptStringEncode()` before embedding it into the script block:

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

            // Encode for JavaScript string context
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
The original code embeds untrusted user input directly into a JavaScript string literal. An attacker can inject a quote to escape the string and inject arbitrary JavaScript, for example: `?q='; alert('XSS'); //` becomes `var lastSearch = ''; alert('XSS'); //';`.

`HttpUtility.JavaScriptStringEncode()` escapes characters that have special meaning in JavaScript strings (quotes, backslashes, forward slashes, etc.), preventing the attacker from breaking out of the string literal. This is the appropriate encoding method for values being placed inside JavaScript code within HTML.
