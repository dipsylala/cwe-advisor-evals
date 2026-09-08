## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation, Cross-Site Scripting)
- **Location**: `JsContextUnencodedOutput.cs`, line 23 (`Response.Write(script)`)

## Source

`Request.QueryString["q"]` (line 14) - the raw, attacker-controlled `q` query-string parameter from the incoming HTTP request. It is assigned to `searchTerm` with no validation or encoding.

## Fix

No third-party library is required; the fix uses `System.Text.Encodings.Web.JavaScriptEncoder`, which ships in the `System.Text.Encodings.Web` NuGet package (Microsoft-maintained, part of the BCL extensions and usable from .NET Framework 4.6.1+ projects such as this Web Forms app). Confirm the resolved package version against SCA/dependency-check tooling before merging; no specific minimum version is prescribed by the loaded guidance.

### File: JsContextUnencodedOutput.cs

```csharp
using System;
using System.Text.Encodings.Web;
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

            // Encode for the JavaScript string-literal context: escapes quotes,
            // backslashes, angle brackets, and U+2028/U+2029 so the value cannot
            // terminate the string literal, break out of the <script> block, or
            // inject new script content.
            string encodedSearchTerm = JavaScriptEncoder.Default.Encode(searchTerm ?? string.Empty);

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

The sink is a hand-built inline `<script>` block emitted with `Response.Write()`, so Razor's auto-encoding and HTML encoding (`HtmlEncode`) do not apply and would not help even if they did: a `<script>` element is raw text, so the browser never HTML-decodes entities there, and the value still has to be safe as a JavaScript string literal. `searchTerm` was concatenated straight into the single-quoted JS string with no encoding, so a value such as `';alert(document.cookie);//` or `</script><script>alert(1)</script>` closes the string literal (or the `<script>` tag itself) and lets the attacker run arbitrary script in the victim's session. The fix passes `searchTerm` through `JavaScriptEncoder.Default.Encode()` before it is concatenated. That encoder is designed for exactly this context: it escapes both `'` and `"` (so it cannot terminate the string literal regardless of which quote style wraps it), backslashes, `<`/`>`/`&` (so `</script>` cannot break out of the script element), and the U+2028/U+2029 line terminators that can otherwise truncate a JS string. The value remains inert data assigned to `lastSearch` instead of executable script, closing the injection while leaving the page's existing analytics behavior (calling `trackSearch` with the search term) unchanged. Microsoft's own first recommendation for script contexts - placing the value in a `data-*` attribute and reading it from JavaScript at runtime - would avoid the script-literal context entirely, but doing so here would require restructuring `Page_Load`'s raw `Response.Write` output into a markup element with server-side data binding, which is a larger structural change than this fix warrants; encoding at the point of concatenation is the guidance's stated fallback and fully closes the reported sink.

## Behaviour changes

- Added `?? string.Empty` when passing `searchTerm` into the encoder. `JavaScriptEncoder.Encode()` throws `ArgumentNullException` on a null input, whereas the original string concatenation (`"..." + searchTerm + "..."`) silently treated a null `searchTerm` (e.g., no `q` parameter on the request) as an empty string. The null-coalesce preserves that original behavior - a missing `q` parameter still renders `var lastSearch = '';` - rather than introducing a new exception path.
- The literal text sent by `Response.Write` for a search term containing HTML/JS metacharacters now differs from the original (e.g., a `'` in the input now appears in the response as `'` instead of raw `'`). This is the intended effect of the fix, not an unrelated change: `trackSearch()` still receives the same logical string value in `lastSearch` once the browser's JS engine parses the (now-safe) literal, so the client-side analytics behavior for legitimate search terms is unaffected.
- No other arguments, return values, or control flow were altered; the sink (`Response.Write`, called once, same string concatenation shape, same downstream `trackSearch(lastSearch)` call) is otherwise unchanged.

## Verification

Compiled the fixed file with the real C# compiler via `dotnet build` against a scratch net48 class-library project (Reference Assemblies `.NETFramework v4.8`) with a `<Reference Include="System.Web" />` and `<PackageReference Include="System.Text.Encodings.Web" Version="8.0.0" />`, mirroring this Web Forms project's dependencies. Build succeeded: 0 warnings, 0 errors. This confirms `System.Text.Encodings.Web.JavaScriptEncoder.Default.Encode(string)` exists with the signature used, that the `using System.Text.Encodings.Web;` import resolves, and that the file is otherwise syntactically and semantically valid against `System.Web.UI.Page`'s `Request`/`Response` members.

Assumption: none needed beyond the above - the CWE ID, language, and sink were unambiguous from the finding and the marked comment at line 23.
