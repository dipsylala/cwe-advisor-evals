## Verdict

The vulnerability is confirmed. The template on line 26 uses `th:utext="${note}"`, which renders user-controlled input unescaped. This allows attacker-supplied HTML and JavaScript to execute in the browser.

## Source

Line 26 in the template fragment:
```
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

The `th:utext` attribute processes the variable without HTML escaping, and the `submitterNote` parameter flows directly into the `note` context variable (line 29) without sanitization.

## Fix

Change `th:utext` to `th:text` on line 26:

```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

This single-word change switches from unescaped rendering to escaped rendering. The Thymeleaf engine will now convert HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, etc.), preventing injected scripts from executing.

## Explanation

Thymeleaf's `th:utext` and `th:text` attributes differ in escaping behavior. The `th:text` attribute is the secure default: it HTML-escapes the variable before rendering, neutralizing script injection. The `th:utext` attribute intentionally bypasses escaping and is reserved for trusted, pre-sanitized content only—not user input.

Since `submitterNote` originates from a request parameter and is not validated or sanitized before use, it must be treated as untrusted. Switching to `th:text` ensures the browser renders it as plain text, not as executable markup.
