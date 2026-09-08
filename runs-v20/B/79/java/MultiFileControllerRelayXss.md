## Verdict

Exploitable. CWE-79 (Improper Neutralization of Input During Web Page Generation, Cross-Site Scripting), confirmed at `FeedbackRenderer.java:36` (the `out.println(html)` call). Confidence: high.

## Source

- **Sources**: `HttpServletRequest.getParameter("comment")` and `HttpServletRequest.getParameter("author")` in `FeedbackController.handleSubmit`. Both are attacker-controlled request parameters; the only transformation applied is a null-to-default substitution (`""` / `"Anonymous"`), which does not neutralize any HTML metacharacters.
- **Flow**: `handleSubmit` wraps the raw values in a `FeedbackRenderer.FeedbackSubmission` (`authorName`, `comment`) and passes it unchanged to `renderer.renderConfirmation(submission, response)`.
- **Sink**: `renderConfirmation` string-concatenates `submission.authorName` and `submission.comment` directly into an HTML document (`<h1>...` and `<p>...` respectively) and writes it with `response.getWriter().println(html)` after `setContentType("text/html")`. Neither field is encoded before concatenation, so a value such as `"><script>...</script>` in either `author` or `comment` breaks out of the surrounding markup and executes in the victim's browser. No validation, encoding, or templating engine sits between source and sink anywhere in the two-file chain.

## Fix

### File: FeedbackRenderer.java

```java
package com.example.feedback;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.logging.Logger;
import org.owasp.encoder.Encode;

public class FeedbackRenderer {

    private static final Logger LOG = Logger.getLogger(FeedbackRenderer.class.getName());

    public static class FeedbackSubmission {
        final String authorName;
        final String comment;
        final Instant submittedAt;

        FeedbackSubmission(String authorName, String comment, Instant submittedAt) {
            this.authorName = authorName;
            this.comment = comment;
            this.submittedAt = submittedAt;
        }
    }

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
}
```

This fix depends on the OWASP Java Encoder library (Maven artifact `org.owasp.encoder:encoder`, class `org.owasp.encoder.Encode`). Confirm the resolved version against SCA/dependency-check tooling before merging; no minimum safe version is asserted here from memory. Add it as a compile dependency wherever the project declares its dependencies (e.g. `pom.xml` `<dependency><groupId>org.owasp.encoder</groupId><artifactId>encoder</artifactId><version>...</version></dependency>` or the Gradle equivalent) - `FeedbackController.java` is unrelated to the sink and is not changed.

## Explanation

Both `authorName` and `comment` are plain user-supplied text destined for an HTML body context, not markup the application intends to preserve, so the correct defence is context-appropriate output encoding at the point of concatenation rather than a sanitizer or a template-engine swap. `Encode.forHtml()` from the OWASP Java Encoder converts `<`, `>`, `&`, `"`, `'` and other HTML-significant characters into their entity equivalents immediately before they enter the `<h1>` and `<p>` elements, so an injected `<script>` or attribute-breakout payload renders as inert text instead of being parsed as markup. Encoding is applied at the single sink where the values reach the response body, matching the CWE-79 guidance's per-sink (not per-input) encoding rule, and leaves the rest of the method - logging, content-type header, `println` call - untouched.

**Verification**: the fixed file was copied to a scratch directory alongside minimal stand-in declarations for `javax.servlet.http.HttpServletResponse`/`HttpServletRequest` and `org.owasp.encoder.Encode` (matching the real APIs' signatures) and compiled with `javac` (build 26) - it compiled with no errors or warnings. The real `org.owasp.encoder:encoder` jar was not available in this environment to compile against, so the dependency's existence and API surface (`Encode.forHtml(String)`) are taken from the loaded CWE-79 Java guidance rather than a live library check; the project's own build should resolve and compile against the actual artifact before merging.

## Behaviour changes

- Added `import org.owasp.encoder.Encode;` and wrapped `submission.authorName` and `submission.comment` in `Encode.forHtml(...)` before concatenation - this is the encoding fix itself, not incidental.
- No other change: the method's signature, `throws IOException`, logging statement, `setContentType` call, `PrintWriter` acquisition, and the `println(html)` sink call are all unchanged, so the sink's existing contract (void return, no discarded output, `IOException` propagation on write failure) is preserved.
- Functional effect visible to a client: a comment or author name containing literal `<`, `>`, `&`, `"`, or `'` now renders those characters as their HTML entities in the confirmation page's source instead of as raw characters - the browser still displays the original characters to the user, but the page's HTML source differs. This is the intended effect of closing the XSS and is not a regression.
- Assumptions: neither `authorName` nor `comment` is intended to carry HTML markup (both are ordinary form-submitted text fields), so `Encode.forHtml()` is the correct primitive rather than the OWASP Java HTML Sanitizer; if either field is meant to accept rich text in this application, the fix point would instead need an allowlist sanitizer and this assumption should be revisited. `FeedbackController.java` requires no change since it only relays the raw values without opening a second unencoded sink.
