## Verdict

**CONFIRMED**: CWE-79 (Cross-site Scripting). Untrusted user input from HTTP request parameters (`author` and `comment`) is concatenated directly into HTML output without encoding at the XSS sink `PrintWriter.println()`.

## Source

`FeedbackController.handleSubmit()` lines 13 and 17 retrieve untrusted data from HTTP request parameters:
- `request.getParameter("comment")` → assigned to `rawComment`
- `request.getParameter("author")` → assigned to `authorName`

These values are passed to `FeedbackRenderer.FeedbackSubmission` and subsequently to `renderConfirmation()`.

## Fix

### File: FeedbackRenderer.java

```java
package com.example.feedback;

import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;
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

The fix applies context-appropriate HTML encoding using OWASP Java Encoder's `Encode.forHtml()` method at the point where untrusted data is embedded into HTML. By encoding both `submission.authorName` and `submission.comment` before concatenation into the HTML string, special characters like `<`, `>`, `&`, `"`, and `'` are converted to HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This prevents injected JavaScript payloads from being interpreted as executable code in the browser, while allowing legitimate content containing these characters to render correctly.

The OWASP Java Encoder library (`org.owasp.encoder:encoder`) is added as an import, and the encoding is applied at the HTML body context where the data appears, satisfying both the primary defence (output encoding) and the context-specific requirement established in the Java guidance.

## Behaviour changes

- User input containing HTML-like characters (e.g., `<`, `>`, `&`, quotes) will now be rendered as literal text (HTML entities) instead of being interpreted as HTML markup
- Legitimate feedback containing such characters will display correctly (e.g., "Tom & Jerry" displays as "Tom &amp; Jerry")
- XSS payloads such as `<img src=x onerror="alert('XSS')">` are neutralized and display as literal text
- No functional regression: the confirmation message still displays as intended, with improved security
