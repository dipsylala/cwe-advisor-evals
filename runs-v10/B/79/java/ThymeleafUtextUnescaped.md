## Verdict

Exploitable. User input from the `submitterNote` HTTP parameter is directly rendered without HTML encoding via Thymeleaf's `th:utext` attribute, allowing arbitrary JavaScript injection.

## Source

Line 24: `@RequestParam("note") String submitterNote` - untrusted HTTP request parameter

Data flows to line 29 where it is stored in the template context with key "note", then rendered at line 32 through a template fragment using `th:utext="${note}"`.

## Fix

**Vulnerable code (line 26):**
```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

**Fixed code:**
```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

Replace `th:utext` with `th:text`. The `th:text` attribute performs context-aware HTML entity encoding by default in Thymeleaf.

## Explanation

The vulnerability exists because `th:utext` is a Thymeleaf escaping opt-out directive that renders content as raw HTML without encoding special characters. By switching to `th:text`, Thymeleaf will automatically apply HTML entity encoding, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that user-supplied content like `<script>alert('XSS')</script>` will be rendered as literal text in the HTML output rather than interpreted as executable code. The fix aligns with the core principle that all untrusted output must be encoded at each sink according to its rendering context.

## Behaviour changes

None. The `th:text` attribute produces the same output as `th:utext` for legitimate (non-markup) input. For content containing HTML characters, `th:text` will render them as escaped entities visible to the user (e.g., a user-submitted string containing `<tag>` will appear as the literal text `<tag>` instead of being interpreted as an HTML tag). This is the intended and safe behavior for displaying user-controlled data in a preview context.
