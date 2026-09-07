## Verdict

Exploitable. The vulnerability is a JavaScript context XSS where untrusted user input from `Request.QueryString["q"]` is embedded directly into a JavaScript string literal without any encoding, allowing an attacker to break out of the string and execute arbitrary JavaScript in the victim's browser.

## Source

- **CWE ID**: CWE-79
- **Vulnerability**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **File**: JsContextUnencodedOutput.cs
- **Line**: 23
- **Confidence**: High

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

            // Encode the value for safe insertion into an HTML attribute (data attribute)
            string encodedSearchTerm = HttpUtility.HtmlEncode(searchTerm);

            string script =
                "<div id='searchData' data-search=\"" + encodedSearchTerm + "\"></div>" +
                "<script>" +
                "var lastSearch = document.getElementById('searchData').getAttribute('data-search');" +
                "trackSearch(lastSearch);" +
                "</script>";

            Response.Write(script);
        }
    }
}
```

## Explanation

The fix eliminates the JavaScript context XSS vulnerability by moving the untrusted data out of the script source and into an HTML attribute where it cannot be interpreted as code. The remediation follows the CWE-79 C# guidance's preferred approach: embedding the value in a data attribute on an HTML element and reading it from JavaScript at runtime, rather than constructing JavaScript string literals with untrusted input.

The `searchTerm` value is HTML-encoded using `HttpUtility.HtmlEncode()` before being placed in the `data-search` attribute. This encoding prevents attribute breakout attacks (e.g., closing the attribute with a quote and injecting additional attributes). The JavaScript then retrieves this value using `getAttribute()`, which returns the decoded attribute value as a plain string—bypassing any JavaScript parsing context. This approach is more secure than escaping the value for JavaScript string context because it eliminates the script source as an attack surface altogether.

## Behaviour changes

The fix changes how `lastSearch` receives its value: instead of being a literal in the JavaScript source code, it is now read from a DOM element's attribute at runtime. This is a transparent change—the variable ends up with the same string value either way, and the `trackSearch()` call receives the same data. No other behaviour changes. The fix preserves the original API contract: `Response.Write()` still outputs the same HTML and script, just with the attack surface eliminated.
