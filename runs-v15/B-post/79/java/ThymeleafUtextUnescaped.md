## Verdict

Vulnerable - CWE-79 exploitable through untrusted user input rendered unescaped in HTML.

## Source

User-controlled input flows from HTTP request parameter `note` (line 24, `@RequestParam("note") String submitterNote`) through the template context at line 29 (`context.setVariable("note", submitterNote)`). The `submitterNote` is untrusted and unconstrained.

## Fix

Change line 26 from:
```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

to:
```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

Replace `th:utext` with `th:text`. Thymeleaf's `th:text` directive applies HTML entity encoding to the output, escaping `<`, `>`, `&`, `'`, and `"` as HTML entities, preventing script injection.

## Explanation

The original code uses Thymeleaf's `th:utext` directive, which renders untrusted data without HTML escaping. An attacker can inject arbitrary HTML and JavaScript through the `note` parameter—for example, `<img src=x onerror="alert('XSS')">` would execute in the victim's browser. The fix switches to `th:text`, which treats the value as text data and applies context-specific HTML entity encoding at the output sink. This encoding renders HTML metacharacters as safe entity references, so injected tags and scripts appear as literal text in the page rather than executable code. Since the code renders user-submitted notes (text, not intentional markup), this escaping is the correct defense.

## Behaviour changes

User input containing HTML characters (`<`, `>`, `&`, quotes) now renders as escaped entities rather than raw HTML. For example, a note containing `<b>bold</b>` displays as the literal text `<b>bold</b>` instead of bold text. This is the intended behavior for treating untrusted input as text data. If the application later requires rich-text support, the remedy is sanitization with an allowlist policy (OWASP Java HTML Sanitizer) applied server-side before rendering, not re-enabling unescaped output.
