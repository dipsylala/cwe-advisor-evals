## Verdict

Exploitable XSS vulnerability confirmed. Untrusted user input from request parameters (`comment` and `author`) flows directly into HTML output at line 36 without encoding.

## Source

**FeedbackController.handleSubmit()** (lines 13, 17):
- `request.getParameter("comment")` - attacker-controlled
- `request.getParameter("author")` - attacker-controlled

These untrusted values are passed into `FeedbackSubmission` and relayed to the renderer without validation or encoding.

## Fix

**File: FeedbackRenderer.java**

Add import at the top:
```java
import org.owasp.encoder.Encode;
```

Replace lines 28-31:
```java
        String html = "<html><body>"
                + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
                + "<p>You said: " + submission.comment + "</p>"
                + "</body></html>";
```

With:
```java
        String html = "<html><body>"
                + "<h1>Thanks for your feedback, " + Encode.forHtml(submission.authorName) + "!</h1>"
                + "<p>You said: " + Encode.forHtml(submission.comment) + "</p>"
                + "</body></html>";
```

## Explanation

The vulnerability occurs because user-controlled strings from `FeedbackSubmission` (populated by request parameters in `FeedbackController`) are concatenated directly into HTML without encoding. An attacker can inject arbitrary HTML and JavaScript through the `author` or `comment` parameters—for example, `"><img src=x onerror=alert(1)>` in the author field will execute script in the victim's browser.

The fix applies OWASP Java Encoder's `Encode.forHtml()` method at the point where user data is embedded in HTML content. This encoding method:
- Converts `<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`, and quotes as needed
- Transforms injection payloads into literal text that browsers render as display content, not executable code
- Works for HTML body context (not attributes, script blocks, or URLs—which would require different encoding methods)

The `Encode.forHtml()` call is applied directly at the concatenation point, so the user input is never stored as unencoded HTML; the encoded result is what goes into the response.

## Behaviour changes

The fixed code outputs user-controlled content as HTML-safe text:
- Input like `<img src=x onerror=alert(1)>` will render as literal text to the user, not execute script
- Legitimate content containing `<`, `>`, `&`, and quotes is still displayed correctly, rendered as HTML entities
- No change to the response structure, HTTP headers, or application flow—only the unsafe strings become safe
