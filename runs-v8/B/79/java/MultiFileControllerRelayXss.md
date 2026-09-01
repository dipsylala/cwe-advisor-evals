## Verdict

Exploitable. Untrusted request parameters flow directly into HTML output without encoding, allowing script injection.

## Source

`FeedbackController.handleSubmit()` receives untrusted data from request parameters:
- Line 13: `String rawComment = request.getParameter("comment");`
- Line 17: `String authorName = request.getParameter("author");`

These values are passed to `FeedbackRenderer.FeedbackSubmission` and subsequently used in HTML construction.

## Fix

**Vulnerable code** (FeedbackRenderer.java, lines 28-31):
```java
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
        + "<p>You said: " + submission.comment + "</p>"
        + "</body></html>";
```

**Fixed code**:
```java
import org.owasp.encoder.Encode;

// ... in renderConfirmation method:
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + Encode.forHtml(submission.authorName) + "!</h1>"
        + "<p>You said: " + Encode.forHtml(submission.comment) + "</p>"
        + "</body></html>";
```

**Library recommendation**: OWASP Java Encoder. The guidance names no minimum version, so confirm the resolved version against SCA/dependency-check tooling before merging.

## Explanation

The vulnerability occurs because `submission.authorName` and `submission.comment` contain untrusted request parameters that are concatenated directly into HTML without encoding. When the HTML is written to the response via `PrintWriter.println()` at line 36, a browser parsing the response will execute any scripts embedded in these values. The fix applies `Encode.forHtml()` at each injection point, converting characters with special meaning in HTML (`<`, `>`, `&`, `"`, `'`) to their entity-encoded equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that even if an attacker injects `<script>alert('xss')</script>` as the author name or comment, it will be rendered as text rather than executed as code. `Encode.forHtml()` is the correct context-aware encoder for HTML body content and must be applied at the output sink, not on input, because a value encoded for one context (HTML body) remains unsafe in others (`<script>` block, attribute, URL, CSS).

## Behaviour changes

None. The fix preserves the sink contract (`PrintWriter.println()` still writes the HTML string to the response) and the displayed output. Legitimate content containing `<`, `>`, `&`, `"`, and `'` characters still renders correctly as encoded entities, which browsers display as their literal characters.
