## Verdict

True positive. Untrusted data from HTTP request parameters flows directly into HTML output without escaping, enabling reflected XSS.

## Source

`FeedbackController.handleSubmit()` retrieves untrusted user input from HTTP request parameters:
- `request.getParameter("comment")` (line 13)
- `request.getParameter("author")` (line 17)

These values are passed directly to `FeedbackSubmission` constructor without sanitization.

## Fix

Escape the untrusted strings using HTML entity encoding before embedding them into the HTML output. Modify `FeedbackRenderer.renderConfirmation()` to escape both `submission.authorName` and `submission.comment`:

```java
import org.apache.commons.text.StringEscapeUtils;

public void renderConfirmation(FeedbackSubmission submission, HttpServletResponse response) throws IOException {
    LOG.info("Feedback received at " + submission.submittedAt);

    String escapedAuthorName = StringEscapeUtils.escapeHtml4(submission.authorName);
    String escapedComment = StringEscapeUtils.escapeHtml4(submission.comment);

    String html = "<html><body>"
            + "<h1>Thanks for your feedback, " + escapedAuthorName + "!</h1>"
            + "<p>You said: " + escapedComment + "</p>"
            + "</body></html>";

    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println(html);
}
```

Add dependency: `org.apache.commons:commons-text:1.11.0` (or later).

## Explanation

The vulnerability occurs because user-controlled input from HTTP request parameters is directly concatenated into an HTML string without escaping. If an attacker submits `<script>alert('XSS')</script>` as the comment or author name, it will be written literally into the HTML response, causing the browser to execute the script in the context of the user's session.

HTML entity encoding converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their harmless entity representations (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting the data as HTML markup or script tags. This is the primary defence for context-specific output encoding in HTML contexts.

The use of `StringEscapeUtils.escapeHtml4()` from Apache Commons Text is the idiomatic Java approach and ensures all necessary characters are properly escaped for HTML content contexts.
