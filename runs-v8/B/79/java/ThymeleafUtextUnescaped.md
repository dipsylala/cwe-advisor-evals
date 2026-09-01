## Verdict

Exploitable. Untrusted user input flows without encoding through Thymeleaf's `th:utext` escape-bypass directive to HTML output.

## Source

`@RequestParam("note") String submitterNote` (line 24) — untrusted HTTP request parameter

## Sink

`th:utext="${note}"` (line 26) processed by `templateEngine.process(fragment, context)` (line 32) — explicit escape-bypass directive that renders unencoded HTML

## Fix

**Vulnerable code:**
```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

**Fixed code:**
```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

Replace the escape-bypass `th:utext` with Thymeleaf's escaping `th:text` directive, which applies automatic HTML entity encoding to the output value.

## Explanation

The vulnerability occurs because `th:utext` explicitly bypasses Thymeleaf's auto-escaping, rendering the value as raw HTML. An attacker can inject script tags or event handlers through the user-supplied note parameter. Replacing `th:utext` with `th:text` enables Thymeleaf's default HTML encoding, which converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entities. This prevents the browser from interpreting user input as markup or executable code while preserving legitimate content display.

## Behaviour changes

No changes to return type or sink contract. The `templateEngine.process()` method continues to return an HTML string. When rendering legitimate content containing `<`, `>`, `&`, `"`, or `'`, these characters are now HTML-encoded in the output (e.g., `<` becomes `&lt;`). This is the intended behavior and the correct fix for XSS.
