## Verdict

Fixed.

## Source

ThymeleafUtextUnescaped.java, line 26: The template fragment uses `th:utext="${note}"` to render user-supplied input without HTML escaping. The `note` parameter (line 24) comes directly from an HTTP request parameter (`@RequestParam`) and flows through the Thymeleaf context (line 29) to the template engine's output (line 32) without validation or encoding. An attacker can inject JavaScript via the note field to execute in the victim's browser.

## Fix

Change line 26 from:

```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

To:

```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

Replace `th:utext` (unescaped text) with `th:text` (escaped text). Thymeleaf's `th:text` directive automatically applies HTML entity encoding to the variable value, converting `<`, `>`, `&`, `"`, and `'` to their safe entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`).

## Explanation

The vulnerability exists because `th:utext` renders its value as raw HTML without any escaping. When untrusted data from a user reaches a `th:utext` sink, malicious scripts execute in the victim's browser context. By switching to `th:text`, the template engine applies context-appropriate HTML entity encoding automatically. This encoding treats the user input as plain text and renders any embedded HTML/JavaScript syntax as literal characters visible to the user, preventing script execution.

The remediation does not require an external library—Thymeleaf's built-in escaping mechanism is sufficient for this use case. There is no indication the note field should contain HTML markup (it is a plaintext support ticket note), so escaping is the correct fix, not sanitization.

## Behaviour changes

- User input containing `<script>alert('xss')</script>` will now render as literal text: `&lt;script&gt;alert('xss')&lt;/script&gt;` visible in the browser, rather than executing as JavaScript.
- Any HTML-like content (tags, entities) in the note will display as plaintext to end users, which is the intended behavior for a support ticket note field.
- The response remains valid HTML with no functional impact on the application—legitimate note content (including accidental or intentional `<`, `&`, or quotes) will display correctly.
