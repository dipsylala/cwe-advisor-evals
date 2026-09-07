## Verdict
exploitable

## Source
User input from `request.getParameter("comment")` and `request.getParameter("author")` in FeedbackController.handleSubmit() (lines 13, 17).

## Fix
**Library recommendation**: OWASP Java Encoder (org.owasp.encoder:encoder).

**Vulnerable code** (FeedbackRenderer.java lines 28-31):
```java
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
        + "<p>You said: " + submission.comment + "</p>"
        + "</body></html>";
```

**Fixed code**:
```java
import org.owasp.encoder.Encode;

String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + Encode.forHtml(submission.authorName) + "!</h1>"
        + "<p>You said: " + Encode.forHtml(submission.comment) + "</p>"
        + "</body></html>";
```

## Explanation
The vulnerability occurs because untrusted user input (authorName and comment) is concatenated directly into HTML content without encoding. An attacker can inject malicious JavaScript through either field, such as `<img src=x onerror=alert('XSS')>`, which executes in the victim's browser. The fix applies OWASP Java Encoder's `Encode.forHtml()` method to both user-controlled values before HTML inclusion. This method encodes HTML special characters (`<`, `>`, `&`, `"`, `'`) as numeric entities, rendering them as literal text in the browser rather than executable code. The encoding is context-appropriate for HTML body content, where these five characters are the complete set requiring escaping.

## Behaviour changes
**Argument added to HTML context**: The fixed code supplies `Encode.forHtml()` calls for both `submission.authorName` and `submission.comment`, transforming the values before string concatenation. The rendering sink (`out.println()`) and its contract remain unchanged; the HTML string passed to it is now safe to output. Characters like `<`, `>`, and `&` in legitimate user input (e.g., "Feedback & Comments") are encoded to `&lt;`, `&gt;`, and `&amp;`, appearing correctly in the browser while preventing code injection. No other output behavior changes.
