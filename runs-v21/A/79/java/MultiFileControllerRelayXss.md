## Verdict
CONFIRMED. The FeedbackRenderer class has a reflected XSS vulnerability at line 36 where unsanitized user input (authorName and comment) from the HTTP request is directly embedded into HTML output without escaping.

## Source
The vulnerability originates in FeedbackController.handleSubmit(), which retrieves untrusted user input from HTTP request parameters:
- `request.getParameter("comment")` - user-supplied comment text
- `request.getParameter("author")` - user-supplied author name

These parameters are passed directly to FeedbackRenderer.FeedbackSubmission without any validation or sanitization, and then rendered into HTML in the renderConfirmation() method.

## Fix

### File: FeedbackRenderer.java
```java
package com.example.feedback;

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

        String escapedAuthorName = escapeHtml(submission.authorName);
        String escapedComment = escapeHtml(submission.comment);

        String html = "<html><body>"
                + "<h1>Thanks for your feedback, " + escapedAuthorName + "!</h1>"
                + "<p>You said: " + escapedComment + "</p>"
                + "</body></html>";

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(html);
    }

    private static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }
}
```

## Explanation
The fix applies output encoding to both user-supplied values before embedding them in the HTML response. The escapeHtml() method converts dangerous characters to their HTML entity equivalents:

- `&` → `&amp;` (escaped first to avoid double-escaping)
- `<` → `&lt;` (prevents tag injection)
- `>` → `&gt;` (prevents tag closing)
- `"` → `&quot;` (prevents attribute breakout)
- `'` → `&#x27;` (prevents single-quote attribute breakout)

This encoding ensures that any special characters in the user input are rendered as text rather than interpreted as HTML or JavaScript. An attacker payload like `<script>alert('XSS')</script>` will be safely rendered as literal text in the browser, not executed.

The escapeHtml() method is a self-contained utility that follows the OWASP HTML entity encoding standard, making no assumptions about context and protecting against XSS in both text nodes and attribute contexts within the HTML structure.
