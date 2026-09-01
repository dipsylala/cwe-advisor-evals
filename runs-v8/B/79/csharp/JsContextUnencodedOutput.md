## Verdict

Exploitable. Untrusted input from `Request.QueryString["q"]` is directly concatenated into a JavaScript string literal without encoding, allowing an attacker to break out of the string and inject arbitrary JavaScript code.

## Source

Line 14: `string searchTerm = Request.QueryString["q"];`

Untrusted user input from the query string parameter `q`.

## Fix

**Vulnerable code (lines 16-23):**
```csharp
string script =
    "<script>" +
    "var lastSearch = '" + searchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
Response.Write(script);
```

**Fixed code:**
```csharp
// Encode for JavaScript string context
string encodedSearchTerm = JavaScriptEncoder.Default.Encode(searchTerm);

string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

**Required import (add to top of file):**
```csharp
using System.Text.Encodings.Web;
```

## Explanation

The vulnerability occurs because untrusted query string input is embedded directly into JavaScript code within a `<script>` tag. An attacker can inject a payload like `'; alert('xss'); var x = '` to break out of the string literal and execute arbitrary JavaScript. The fix applies `JavaScriptEncoder.Default.Encode()`, which properly escapes the input for JavaScript string context by encoding characters like single quotes, backslashes, and line terminators that can break the literal. HTML encoding is insufficient here because the browser does not decode entities inside `<script>` blocks. This encoding approach ensures the value remains data, never executable code, while preserving the original application logic.

## Behaviour changes

- Added `using System.Text.Encodings.Web;` import: required to access `JavaScriptEncoder`
- Introduced intermediate variable `encodedSearchTerm` to hold the encoded value: improves readability and ensures the original untrusted value is never used downstream
- `Response.Write()` still receives the same script markup with the same structure and contract, but now with safely encoded user data; no change to output or error handling
