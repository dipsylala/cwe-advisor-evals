## Verdict

Exploitable. Untrusted user input (authorName and comment) flows directly from request parameters into HTML output without encoding, allowing arbitrary script injection.

## Source

Untrusted input sources:
- `request.getParameter("comment")` in FeedbackController line 13
- `request.getParameter("author")` in FeedbackController line 17

Both values flow through FeedbackRenderer.FeedbackSubmission constructor to FeedbackRenderer.renderConfirmation().

## Fix

**Vulnerable code (FeedbackRenderer.java lines 28-36):**

```java
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
        + "<p>You said: " + submission.comment + "</p>"
        + "</body></html>";

response.setContentType("text/html");
PrintWriter out = response.getWriter();
// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
out.println(html);
```

**Fixed code (FeedbackRenderer.java):**

```java
import org.owasp.encoder.Encode;

// ... (class declaration unchanged) ...

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
```

**Dependency requirement:**

Add OWASP Java Encoder to project dependencies. Consult your SCA tooling or Maven Central for the current stable version and any known security advisories.

## Explanation

The fix applies context-aware output encoding using OWASP Java Encoder's `Encode.forHtml()` method to both `submission.authorName` and `submission.comment` before they are concatenated into the HTML string. `Encode.forHtml()` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents, ensuring the user-supplied text is treated as data rather than markup. This prevents script injection vectors such as `<img src=x onerror=alert(1)>` or `"><script>alert(1)</script>` from executing. The encoding is applied at the point where untrusted data enters the HTML body context, which is the correct location per the CWE-79 guidance requiring context-specific encoding at each output sink.

## Behaviour changes

None. The fix preserves the original sink contract: `out.println(html)` still writes the complete HTML response to the servlet output stream. Legitimate content containing HTML-special characters (e.g., `Price: $100 & up`, `Email: user@host`) is now rendered correctly as text, where it was previously a potential injection vector. No additional output is produced, no encoding happens outside the concatenation point, and error handling remains unchanged.
