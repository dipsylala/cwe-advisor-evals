## Verdict

Exploitable. Untrusted user input from the `submitterNote` parameter flows directly to an XSS sink without escaping.

## Source

- **Untrusted source:** `submitterNote` parameter from `@RequestParam("note")` on line 24 — comes directly from HTTP request query/form data
- **Data flow:** The parameter is placed into a Thymeleaf context variable `note` on line 29, then rendered via the `th:utext` directive in the template fragment on line 26
- **Sink:** `templateEngine.process(fragment, context)` on line 32, specifically the `th:utext="${note}"` rendering instruction in the fragment, which outputs HTML without escaping any special characters

## Fix

**Vulnerable code (line 26):**
```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

**Fixed code:**
```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

Change the `th:utext` directive to `th:text`. The `utext` variant renders raw, unescaped HTML; `th:text` escapes HTML entities automatically.

## Explanation

The vulnerability occurs because `th:utext` renders the context variable without HTML escaping, allowing an attacker to inject malicious script tags in the `note` parameter. For example, a note containing `<img src=x onerror=alert('XSS')>` would execute in the victim's browser. By switching to `th:text`, Thymeleaf automatically HTML-encodes the output, converting dangerous characters: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and quotes are escaped. This transforms injected markup into literal text, rendering it harmless while preserving the intended display of the user's note. Since the use case is displaying plain-text user input (not rich HTML markup), escaping is the correct and intended behavior.

## Behaviour changes

None. The fix restores the correct default escaping behavior. `th:text` is the security-safe default for Thymeleaf when rendering untrusted content. The original code incorrectly used the unescaped variant. No functional regression occurs—legitimate special characters in the note (`<`, `>`, `&`, quotes) are now displayed as their HTML entities, which is the expected behavior for plain-text content. If the field were intentionally meant to carry markup (e.g., a rich-text editor output), sanitization with the OWASP Java HTML Sanitizer would be required instead, paired with `th:utext` for the sanitized output.
