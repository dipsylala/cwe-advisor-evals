## Verdict

Confirmed. CWE-79 (Improper Neutralization of Input During Web Page Generation - Cross-site Scripting) in `FeedbackRenderer.java` at line 36.

## Source

User input flows from HTTP request parameters in `FeedbackController.handleSubmit()`:
- `request.getParameter("comment")` (line 13)
- `request.getParameter("author")` (line 17)

Both parameters are passed unsanitized into `FeedbackRenderer.FeedbackSubmission` and then directly concatenated into an HTML string.

## Fix

Apply HTML entity escaping to both `submission.authorName` and `submission.comment` before including them in the HTML output. Here is the corrected `renderConfirmation()` method:

```java
import org.apache.commons.text.StringEscapeUtils;

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
```

Add Apache Commons Text dependency to your project (e.g., in Maven: `commons-text:commons-text:1.10.0` or later).

## Explanation

The vulnerability exists because untrusted user input is directly embedded into HTML without escaping. An attacker can inject malicious JavaScript by providing input like `author=<script>alert('XSS')</script>`, which will execute when the HTML is rendered in the browser.

The fix uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to convert dangerous HTML characters (`<`, `>`, `"`, `&`, etc.) into their corresponding HTML entity references (`&lt;`, `&gt;`, `&quot;`, `&amp;`, etc.). This ensures that user input is rendered as text content rather than executable HTML or JavaScript.

This escaping is applied at the output sink (line 36 where `out.println()` writes to the response) by first escaping the untrusted values before they are concatenated into the HTML string.
