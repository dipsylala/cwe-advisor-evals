## Verdict

**CONFIRMED** — The vulnerability is real. User-controlled input flows directly to Thymeleaf's `th:utext` directive, which does not escape HTML entities, allowing arbitrary script injection.

## Source

`submitterNote` parameter at line 24 is read from the request via `@RequestParam("note")` with no validation or sanitization.

## Fix

Replace `th:utext` with `th:text` in the fragment at line 26:

```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

## Explanation

The `th:utext` directive renders content without HTML escaping, passing user input directly to the HTML output. An attacker can inject scripts such as `<script>alert('XSS')</script>` which will execute in the browser.

The `th:text` directive replaces `th:utext` and applies HTML entity escaping by default. With this change:
- Characters like `<`, `>`, `&`, `"`, and `'` are converted to `&lt;`, `&gt;`, `&amp;`, `&quot;`, and `&#39;` respectively
- The escaped content is rendered as literal text in the HTML, preventing script execution
- The user's intended message is still visible but cannot execute code

This is Thymeleaf's primary XSS defence — always prefer `th:text` over `th:utext` when rendering untrusted input.
