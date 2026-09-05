## Verdict

Exploitable XSS vulnerability confirmed. Untrusted query string input is concatenated directly into a JavaScript string literal without encoding, allowing an attacker to break out of the string and inject arbitrary JavaScript code.

## Source

Line 14: `string searchTerm = Request.QueryString["q"];`

Untrusted user input from the query string parameter `q`.

## Fix

Add `using System.Text.Encodings.Web;` to the imports. Encode the searchTerm before concatenating it into the JavaScript literal:

```csharp
using System;
using System.Text.Encodings.Web;
using System.Web;
using System.Web.UI;

namespace EvalCases
{
    public partial class SearchResultsPage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string searchTerm = Request.QueryString["q"];

            string encodedSearchTerm = JavaScriptEncoder.Default.Encode(searchTerm);
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

The vulnerability exists because untrusted data is placed directly into a JavaScript string context without encoding. JavaScript string context requires specific encoding that differs from HTML encoding—characters like quotes, backslashes, and line terminators must be handled according to JavaScript's string literal rules. `JavaScriptEncoder.Default.Encode()` applies the correct character escaping to ensure the value remains data within the JavaScript string literal, preventing an attacker from breaking out and injecting arbitrary script code. This is the recommended fallback when restructuring to use a data attribute (the preferred approach) is impractical.

## Behaviour changes

The encoded output will escape special characters that have meaning in JavaScript strings. For example:
- Input: `O'Reilly` → Output: `O'Reilly`
- Input: `<script>alert('xss')</script>` → Output escaped to prevent breakout
- Legitimate content like `C++ Programming` will still render correctly in the JavaScript string

The `trackSearch()` function will receive the unencoded value at runtime since it receives the decoded JavaScript string content, preserving the intended functionality while preventing injection attacks.
