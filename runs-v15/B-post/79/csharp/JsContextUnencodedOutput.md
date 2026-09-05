## Verdict

Exploitable. Untrusted input from `Request.QueryString["q"]` flows directly into a JavaScript string literal without encoding, allowing attackers to inject arbitrary JavaScript code.

## Source

**Location:** `evals/cases/79/csharp/JsContextUnencodedOutput/JsContextUnencodedOutput.cs`, line 14–23

**Source:** `Request.QueryString["q"]` (untrusted user input from the query string)

**Sink:** `Response.Write(script)` at line 23, writing an unencoded JavaScript string literal

**Data flow:** The `searchTerm` variable (read from the query string at line 14) is concatenated directly into the JavaScript code within the `<script>` block at line 18, with no encoding. The assembled script is then written to the HTTP response at line 23.

## Fix

**Vulnerable code:**
```csharp
string searchTerm = Request.QueryString["q"];

string script =
    "<script>" +
    "var lastSearch = '" + searchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

**Fixed code:**
```csharp
using System.Text.Encodings.Web;

// ...

string searchTerm = Request.QueryString["q"];

// Encode the search term for JavaScript context to prevent XSS
string encodedSearchTerm = JavaScriptEncoder.Default.Encode(searchTerm);

string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

## Explanation

The fix applies JavaScript-context encoding using `JavaScriptEncoder.Default.Encode()` from `System.Text.Encodings.Web` before embedding the search term into the JavaScript string literal. JavaScript encoding escapes characters that can break out of a string context—including single quotes, backslashes, and Unicode line terminators (U+2028, U+2029)—so the value arrives safely as data, not executable code. HTML encoding is insufficient for this context: it escapes `<` and `&` but leaves entities like `&quot;` uninterpreted inside `<script>` blocks, where the browser treats the element content as raw JavaScript text and does not decode HTML entities. The guidance names this as the appropriate fallback when putting the value in a data attribute (the preferred approach) is impractical.

## Behaviour changes

None. `JavaScriptEncoder.Default.Encode()` returns a string; the fixed code assigns it to `encodedSearchTerm` and uses it in place of the raw `searchTerm` in the concatenation. The final script string, the sink contract (`Response.Write()` writes a string to the response), and the legitimate output (the search term rendered in a JavaScript variable) all remain unchanged—only the injection risk is removed.
