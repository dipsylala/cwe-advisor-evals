## Verdict

Exploitable. Confidence: high.

## Source

`submitterNote`, the `note` request parameter bound via `@RequestParam("note") String submitterNote` on `POST /tickets/preview` (`previewTicketNote`, line 24). Fully attacker-controlled.

## Fix

Vulnerable code (`ThymeleafUtextUnescaped.java`, lines 26-32):

```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";

Context context = new Context();
context.setVariable("note", submitterNote);

// SAST FINDING: CWE-79 ... Sink is the next statement.
return templateEngine.process(fragment, context);
```

Fixed code:

```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";

Context context = new Context();
context.setVariable("note", submitterNote);

return templateEngine.process(fragment, context);
```

## Explanation

The template fragment binds the attacker-controlled `note` variable with Thymeleaf's `th:utext` attribute, which writes its expression result into the element body as raw, unescaped markup. `templateEngine.process(fragment, context)` (line 32) is the sink: it renders the fragment with `note` substituted in and returns the resulting HTML string, which the controller returns directly as the response body, so any HTML or script the caller supplies in `note` is emitted verbatim and executes in the browser that views the preview - a stored/reflected XSS via the `note` parameter. `th:utext` is Thymeleaf's explicit escaping opt-out; the corresponding safe construct for HTML body content is `th:text`, which HTML-entity-encodes the expression result before writing it. Swapping `th:utext` for `th:text` is the complete fix for this sink - no other escaping call is needed because Thymeleaf's `th:text` already performs context-appropriate HTML encoding.

## Behaviour changes

None beyond closing the weakness. The sink's contract is unchanged: `templateEngine.process` still takes the same `fragment` string shape and `context`, still returns a `String` that the controller returns as the response body, and still fails the same way on a template error. The only difference is that `note`'s value now appears HTML-entity-encoded (`<`, `>`, `&`, `'`, `"` escaped) in the rendered `<div>` instead of being inlined as raw markup - legitimate note text containing those characters still displays correctly to the viewer, just as literal text rather than interpreted HTML, which is the intended behavior for a "preview" of user-submitted plain-text notes.
