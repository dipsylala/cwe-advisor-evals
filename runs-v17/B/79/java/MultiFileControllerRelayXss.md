## Verdict

Exploitable. Untrusted user input flows from HttpServletRequest parameters directly into HTML output without encoding.

## Source

HttpServletRequest parameters "comment" and "author" retrieved in FeedbackController.handleSubmit() (lines 13, 17) without validation or sanitization, then passed to FeedbackRenderer.FeedbackSubmission constructor (line 23).

## Fix

Apply context-appropriate HTML entity encoding using OWASP Java Encoder's `Encode.forHtml()` method to both user-controlled fields before they are concatenated into the HTML output.

### File: FeedbackRenderer.java

```java
package com.example.feedback;

import org.owasp.html.Encode;
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

## Explanation

The vulnerability exists because user-supplied data (authorName and comment) from the HTTP request flows directly into HTML output without encoding. An attacker can inject malicious scripts by crafting input like `<img src=x onerror="alert('XSS')">`, which executes in the victim's browser.

The fix adds the `import org.owasp.html.Encode` statement and applies `Encode.forHtml()` to both user-controlled fields before they are inserted into the HTML string. This method performs context-aware HTML entity encoding, converting dangerous characters (<, >, &, ", ') into their entity equivalents (&lt;, &gt;, &amp;, &quot;, &#x27;), ensuring they render as literal text rather than executable HTML markup or script.

## Behaviour changes

None. The fix adds encoding calls only at the points where untrusted data enters the HTML sink. The overall response structure, content type, and output mechanism remain identical. Users see their input displayed safely (with special characters escaped) rather than interpreted as HTML markup.
