## Verdict

exploitable (confidence: high)

CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting'), Java. `FeedbackController.handleSubmit` reads two HTTP request parameters and passes them, unvalidated and unencoded, through `FeedbackRenderer.renderConfirmation` into an HTML string written directly to the response writer.

## Source

- **Source**: `FeedbackController.handleSubmit(HttpServletRequest, HttpServletResponse)` - `request.getParameter("comment")` (line 13) and `request.getParameter("author")` (line 17). Both are only null-checked (defaulted to `""` / `"Anonymous"`); neither is validated or encoded.
- **Flow**: The two values are wrapped in a `FeedbackRenderer.FeedbackSubmission` (lines 22-23) and passed to `renderer.renderConfirmation(submission, response)` (line 24). Inside `renderConfirmation`, `submission.authorName` and `submission.comment` are concatenated directly into an HTML string (`FeedbackRenderer.java` lines 28-31) with no encoding at any point in the chain.
- **Sink**: `PrintWriter out = response.getWriter(); out.println(html);` - `FeedbackRenderer.java` line 36. This writes the attacker-controlled HTML directly into the `text/html` response body.
- **Sink contract**: `println` returns `void`; the caller does nothing with a return value. It discards nothing security-relevant. The `PrintWriter` is obtained with default encoding from `response.getWriter()` - no argument is substituted or added by the fix. On an underlying I/O failure the writer sets an internal error flag (checked via `checkError()`) rather than throwing `IOException` itself; the method signature's `throws IOException` comes from `response.getWriter()`, and that behavior is unaffected by this fix.

## Fix

**Library recommendation**: OWASP Java Encoder (`org.owasp.encoder:encoder`). The guidance in this knowledge base does not carry a minimum safe version for this library; confirm the resolved version against SCA/dependency-check tooling before merging, and add it to `pom.xml` / `build.gradle` if not already a project dependency.

**Vulnerable code** (`FeedbackRenderer.java`, lines 25-37):

```java
public void renderConfirmation(FeedbackSubmission submission, HttpServletResponse response) throws IOException {
    LOG.info("Feedback received at " + submission.submittedAt);

    String html = "<html><body>"
            + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
            + "<p>You said: " + submission.comment + "</p>"
            + "</body></html>";

    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    // SAST FINDING: CWE-79 reported here. Sink is the next statement.
    out.println(html);
}
```

**Fixed code**:

```java
import org.owasp.encoder.Encode;

public void renderConfirmation(FeedbackSubmission submission, HttpServletResponse response) throws IOException {
    LOG.info("Feedback received at " + submission.submittedAt);

    String html = "<html><body>"
            + "<h1>Thanks for your feedback, " + Encode.forHtml(submission.authorName) + "!</h1>"
            + "<p>You said: " + Encode.forHtml(submission.comment) + "</p>"
            + "</body></html>";

    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println(html);
}
```

## Explanation

`submission.authorName` and `submission.comment` originate as raw, attacker-controlled HTTP request parameters in `FeedbackController` and reach an HTML response body with no encoding anywhere along the call chain, letting an attacker submit a payload such as `<script>...</script>` as the `comment` or `author` parameter and have it execute in the victim's browser. Both values are rendered into the same HTML-body text context (inside `<h1>` and `<p>` elements, not inside an attribute, script block, or URL), so wrapping each in `Encode.forHtml()` at the point of concatenation - immediately before it enters the `html` string - is the correct context-specific encoding per the loaded Java guidance, and it is applied at the sink's actual input rather than at the controller, since `renderConfirmation` is where the HTML is assembled.

## Behaviour changes

- `authorName` and `comment` are now HTML-entity-encoded (`<`, `>`, `&`, `"`, `'`, and other HTML-significant characters converted to entities) before being embedded in the response body. Legitimate feedback containing those characters (e.g. "Tom & Jerry", `5 < 10`) will render as the escaped entities' visual equivalent rather than raw characters - this is the intended effect of closing the weakness, not a side effect.
- No other argument, return value, control flow, or output content was altered: `response.setContentType`, the `PrintWriter` acquisition, the logging call, and `out.println(html)` are unchanged; only the two concatenated values are now passed through `Encode.forHtml()` first.
- Adds a new compile-time dependency on the OWASP Java Encoder library, which must be present on the classpath.
