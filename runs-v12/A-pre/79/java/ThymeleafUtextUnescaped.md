## Verdict

CWE-79 confirmed. The application receives untrusted user input via `@RequestParam("note")` and renders it in an HTML template using Thymeleaf's `th:utext` directive without HTML escaping, allowing arbitrary script execution in the browser.

## Source

User-supplied input: `submitterNote` parameter received via `@PostMapping("/tickets/preview")` at line 24.

Data flows from request parameter → Context variable → Thymeleaf template processing at line 32.

## Fix

Replace `th:utext` with `th:text` in the template fragment. The corrected line 26 becomes:

```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

This change alone is sufficient. No other modifications needed.

## Explanation

The `th:utext` directive renders Thymeleaf variables as raw, unescaped HTML. When user input is placed directly into a template processed with `th:utext`, any HTML or JavaScript tags in that input are executed by the browser, enabling stored or reflected XSS attacks.

Thymeleaf's `th:text` directive escapes HTML special characters by default, converting `<`, `>`, `&`, and other metacharacters into their HTML entity equivalents. This rendering prevents the browser from interpreting user-supplied content as markup or script.

The fix is the standard XSS mitigation for Thymeleaf: use `th:text` for all user-controlled variable output unless the value is definitively known to contain safe, pre-validated HTML. Here, the preview is user-editable ticket notes; `th:text` is the correct choice.
