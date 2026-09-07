## Verdict

Exploitable. The `searchTerm` is derived from untrusted query-string input and embedded directly into a JavaScript string literal within a `<script>` block without encoding. An attacker can inject JavaScript by breaking out of the string (e.g., `'; alert(document.domain); //`) or by using line terminators (U+2028, U+2029) that break the JavaScript literal but pass through the HTML parser.

## Source

Untrusted input from `Request.QueryString["q"]` (line 14) flows to the JavaScript sink without encoding.

## Fix

**Vulnerable code (lines 16–20):**
```csharp
string script =
    "<script>" +
    "var lastSearch = '" + searchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";
```

**Fixed code:**
```csharp
string encodedSearchTerm = HttpUtility.JavaScriptStringEncode(searchTerm);

string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";
```

## Explanation

The fix applies `HttpUtility.JavaScriptStringEncode()` to `searchTerm` before embedding it in the JavaScript string literal. This function escapes characters that have special meaning in JavaScript strings—including single and double quotes, backslashes, and line terminators—preventing the attacker from breaking out of the string context or injecting executable code. Since the value is rendered inside a `<script>` block (not an HTML attribute or text node), HTML encoding is insufficient; JavaScript-specific encoding is required.

## Behaviour changes

No significant behaviour changes. `HttpUtility.JavaScriptStringEncode()` preserves the original data, encoding only characters that would be interpreted as structural elements in JavaScript. Legitimate search terms (including those with spaces, punctuation, and Unicode characters) pass through correctly. The size of the output may increase slightly if the input contains characters requiring escape sequences, but the semantic meaning is preserved.
