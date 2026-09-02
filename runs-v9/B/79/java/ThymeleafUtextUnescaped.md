## Verdict

exploitable, high confidence.

## Source

`@RequestParam("note") String submitterNote` on `previewTicketNote` (`ThymeleafUtextUnescaped.java:24`) - fully attacker-controlled HTTP request parameter, no validation or encoding applied anywhere in the method.

## Fix

Vulnerable code (`ThymeleafUtextUnescaped.java:26,29,32`):

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

The only change is `th:utext` to `th:text` on line 26. `context.setVariable` and `templateEngine.process` are unchanged.

## Explanation

`submitterNote` flows unmodified from the `note` request parameter into the Thymeleaf context variable `note`, which the inline fragment renders with `th:utext` - Thymeleaf's explicit unescaped-output attribute. `templateEngine.process` writes that value straight into the HTML response body with no entity encoding, so a payload such as `<img src=x onerror=alert(1)>` submitted as `note` executes in the browser of anyone who views the rendered preview. `th:utext` is Thymeleaf's escaping bypass (the KB's Java guidance lists it as a taint sink); `th:text`, the standard text-rendering attribute, HTML-entity-encodes the resolved expression before writing it, which is the sink's own built-in defence and requires no other code change. Because `resolver.setTemplateMode(TemplateMode.HTML)` is already set, `th:text` escaping applies correctly in this fragment.

## Behaviour changes

None beyond closing the weakness. The method still returns a `String` containing the rendered `<div class="ticket-note">...</div>" fragment with the submitted note inserted in the same position; the only functional difference is that characters `<`, `>`, `&`, `'`, and `"` in the note are now rendered as HTML entities instead of being interpreted as markup, so a note containing literal HTML-like text (e.g. "orders < 5") now displays its escaped form rather than being parsed as tags - this is the intended fix, not a side effect. Return type, arguments, and error/failure behavior of `templateEngine.process` are unchanged.
