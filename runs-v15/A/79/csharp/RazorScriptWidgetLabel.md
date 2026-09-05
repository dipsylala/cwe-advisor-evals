## Verdict

Confirmed XSS vulnerability via unsafe JavaScript embedding.

## Source

Line 7 of Widget.cshtml embeds `Model.Label` directly into a JavaScript object literal using `@Html.Raw()`:

```
label: "@Html.Raw(Model.Label)",
```

The `@Html.Raw()` instruction bypasses all encoding. When `Model.Label` contains a double quote or JavaScript syntax, it escapes the string context and injects arbitrary code. For example, if `Model.Label` is `", alert('XSS')); var x = {"`, the rendered JavaScript becomes:

```javascript
label: "", alert('XSS')); var x = {"",
```

The attacker-supplied text breaks the string boundary and executes.

## Fix

Replace the unsafe raw output with proper JSON encoding for the JavaScript context:

```
label: @System.Text.Json.JsonSerializer.Serialize(Model.Label),
```

This approach:
- Encodes the string as a JSON literal, escaping all special characters (quotes, backslashes, control characters)
- Produces valid JavaScript that cannot break the string boundary
- Is built into the .NET runtime and requires no external dependencies

## Explanation

ASP.NET Razor's default HTML encoding (`@Model.Label` alone) is insufficient for JavaScript contexts because HTML entity encoding (e.g., `"` → `&quot;`) is transparent inside JavaScript strings. The browser parses HTML first, decoding `&quot;` back to `"` before passing the script to the JavaScript engine.

JavaScript contexts require a different escaping strategy: JSON encoding. `System.Text.Json.JsonSerializer.Serialize()` escapes the string as a JSON literal, which is a safe and standard format for embedding untrusted data in JavaScript. The output is a syntactically complete JSON string that cannot escape its boundaries, preventing script injection regardless of the content of `Model.Label`.
