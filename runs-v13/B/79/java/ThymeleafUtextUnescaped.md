## Verdict

Confirmed. Untrusted user input (`submitterNote` from `@RequestParam("note")`) is rendered through Thymeleaf's `th:utext` directive without escaping, allowing arbitrary HTML and JavaScript injection in the browser context.

## Source

Line 24: `submitterNote` is bound directly from the HTTP request parameter with no validation.

Line 26: Template fragment uses `th:utext="${note}"`, which renders the variable as unescaped HTML.

Line 29: The untrusted parameter is assigned to the context variable without transformation.

Line 32: `templateEngine.process()` executes the template with the unescaped directive, producing a response containing the attacker-controlled payload.

**Data flow:** HTTP request parameter → `@RequestParam` binding → context variable → `th:utext` sink → HTTP response body → browser execution.

## Fix

Replace `th:utext` with `th:text` on line 26:

**Before:**
```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

**After:**
```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

No other changes required. The template engine will apply context-aware HTML entity encoding automatically.

## Explanation

The `th:text` directive enables Thymeleaf's built-in output encoding, which escapes dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents. This ensures the value is treated as data, not executable markup or script. The directive is sufficient because the note is rendered into HTML body content (inside a `<div>` element), the context where HTML entity encoding is the appropriate defence. If the intent were to render intentionally-authored HTML (e.g., rich text from a CMS), the fix would require sanitization with an allowlist policy; for a user-submitted note preview, plain text rendering is the correct behavior.

## Behaviour changes

**Before:** A user supplying `<img src=x onerror="alert('hacked')">` in the note parameter would see the JavaScript execute in their browser when the preview renders.

**After:** The same input renders literally as text: `&lt;img src=x onerror="alert('hacked')"&gt;`, printed in the preview without script execution. Legitimate content containing HTML-like syntax (e.g., `"use <tag> syntax"`) displays correctly as literal text rather than being interpreted as markup.

The change closes the XSS without introducing data-model or rendering regressions, as the note field is intended for plain-text user input, not rich HTML content.
