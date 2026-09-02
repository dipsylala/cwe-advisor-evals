## Verdict
Confirmed. This is a reflected cross-site scripting (XSS) vulnerability. User-controlled input from HTTP request parameters is directly embedded into HTML output without sanitization or encoding, allowing an attacker to inject malicious scripts.

## Source
The vulnerability exists in the data flow between two files:

**FeedbackController.java (lines 13, 17-23):** Retrieves unvalidated user input from request parameters:
```
String rawComment = request.getParameter("comment");
String authorName = request.getParameter("author");
```

**FeedbackRenderer.java (lines 28-36):** Embeds this unencoded input directly into HTML:
```
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
        + "<p>You said: " + submission.comment + "</p>"
        + "</body></html>";
out.println(html);
```

An attacker can craft a request with payloads like `?author=<script>alert('XSS')</script>` to inject and execute arbitrary JavaScript in the victim's browser.

## Fix
Add HTML entity encoding to the FeedbackRenderer class. Import `org.apache.commons.lang3.StringEscapeUtils` and apply `escapeHtml4()` to user-supplied values when building the HTML string:

```java
import org.apache.commons.lang3.StringEscapeUtils;

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
```

Alternatively, if Apache Commons Lang is unavailable, use `java.net.URLEncoder.encode()` or implement a custom HTML encoder that converts `<`, `>`, `&`, `"`, `'` to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`).

## Explanation
The fix encodes special HTML characters in user input before they are embedded into the HTML response. `StringEscapeUtils.escapeHtml4()` converts dangerous characters (e.g., `<` becomes `&lt;`, `>` becomes `&gt;`) so they are rendered as literal text rather than interpreted as HTML or JavaScript tags by the browser. This prevents the injected scripts from executing while preserving the user's intended message content. The attacker's payload `<script>alert('XSS')</script>` becomes `&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;`, rendering as visible text rather than executable code.
