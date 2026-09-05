## Verdict
**Confirmed XSS Vulnerability**

The code is vulnerable to cross-site scripting (CWE-79). User-supplied input from HTTP request parameters (`comment` and `author`) flows directly into HTML output without sanitization or escaping.

## Source
**Data Flow:**
1. `FeedbackController.handleSubmit()` receives untrusted input via `request.getParameter("comment")` (line 13) and `request.getParameter("author")` (line 17)
2. These raw values are passed to `FeedbackRenderer.FeedbackSubmission` (lines 22-23)
3. `FeedbackRenderer.renderConfirmation()` directly concatenates these values into an HTML string (lines 29-30)
4. The unescaped HTML is written to the response (line 36)

An attacker can inject arbitrary JavaScript by submitting:
- `author: <script>alert('XSS')</script>`
- `comment: "><img src=x onerror="alert('XSS')"><p>"`

The browser will execute this code in the victim's session, allowing session hijacking, credential theft, or malware distribution.

## Fix
Update `FeedbackRenderer.java` to escape HTML special characters:

```java
package com.example.feedback;

import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringEscapeUtils;
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

        String escapedAuthor = StringEscapeUtils.escapeHtml4(submission.authorName);
        String escapedComment = StringEscapeUtils.escapeHtml4(submission.comment);

        String html = "<html><body>"
                + "<h1>Thanks for your feedback, " + escapedAuthor + "!</h1>"
                + "<p>You said: " + escapedComment + "</p>"
                + "</body></html>";

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(html);
    }
}
```

**Key changes:**
- Import `org.apache.commons.lang3.StringEscapeUtils`
- Escape `submission.authorName` using `StringEscapeUtils.escapeHtml4()`
- Escape `submission.comment` using `StringEscapeUtils.escapeHtml4()`
- Use escaped values in the HTML string

Add the dependency to your project's build configuration:
```
org.apache.commons:commons-lang3:3.12.0 (or later)
```

## Explanation
HTML escaping converts dangerous characters into safe HTML entities:
- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `&` becomes `&amp;`
- `"` becomes `&quot;`
- `'` becomes `&#x27;`

This prevents the browser from interpreting user input as HTML or JavaScript code. An attacker's payload `<script>alert('XSS')</script>` becomes the harmless text `&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;` displayed to the user.

`StringEscapeUtils.escapeHtml4()` from Apache Commons Lang 3 is a widely-used, well-maintained library that properly handles all HTML entity encoding according to the HTML 4 standard, ensuring comprehensive protection against XSS injection in this context.
