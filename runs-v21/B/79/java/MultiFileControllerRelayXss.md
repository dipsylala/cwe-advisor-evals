## Verdict
exploitable

## Source
HTTP request parameters `author` and `comment` (accessed via `request.getParameter()` in FeedbackController) are untrusted user inputs that reach the rendering sink without encoding.

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

## Explanation
The vulnerability occurs because untrusted user input (`submission.authorName` and `submission.comment`) is concatenated directly into an HTML string without any encoding, then written to the response at line 36. An attacker can inject arbitrary HTML and JavaScript by including characters like `<`, `>`, and quotes in the feedback form. The fix applies `Encode.forHtml()` from the OWASP Java Encoder library to both untrusted inputs before concatenation, converting special characters to HTML entities (e.g., `<` becomes `&lt;`, `>` becomes `&gt;`) so they render as literal text rather than executable code. This preserves the HTML structure while preventing script injection. The library import `org.owasp.encoder.Encode` is added to support this context-appropriate encoding.

## Behaviour changes
- Added import: `org.owasp.encoder.Encode` (from artifact `org.owasp.encoder:encoder`)
- Modified line 30: wrapped `submission.authorName` with `Encode.forHtml()` before concatenation
- Modified line 31: wrapped `submission.comment` with `Encode.forHtml()` before concatenation

No changes to method signature, return type, exception handling, or output format. The HTML structure and logging behavior remain identical; only the untrusted values are encoded to prevent injection.
