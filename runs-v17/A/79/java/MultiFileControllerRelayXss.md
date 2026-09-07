## Verdict
CONFIRMED

## Source
Data flows from HTTP request parameters (`request.getParameter("author")` and `request.getParameter("comment")` in FeedbackController) → stored in FeedbackSubmission → rendered unsanitized into HTML via string concatenation in FeedbackRenderer.renderConfirmation().

## Fix

### File: FeedbackRenderer.java

```java
package com.example.feedback;

import org.apache.commons.lang3.StringEscapeUtils;
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
                + "<h1>Thanks for your feedback, " + StringEscapeUtils.escapeHtml4(submission.authorName) + "!</h1>"
                + "<p>You said: " + StringEscapeUtils.escapeHtml4(submission.comment) + "</p>"
                + "</body></html>";

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(html);
    }
}
```

## Explanation
The vulnerability occurs because user-controlled values (`submission.authorName` and `submission.comment`) are concatenated directly into the HTML response without escaping. An attacker can inject HTML/JavaScript: for example, passing `author=<img src=x onerror=alert('xss')>` results in the browser executing the injected script.

The fix wraps both user inputs with `StringEscapeUtils.escapeHtml4()` from Apache Commons Lang 3, which converts HTML special characters (`&`, `<`, `>`, `"`, `'`) to their entity equivalents (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`). This ensures that any HTML/JavaScript in the user input is rendered as text rather than executed by the browser.
