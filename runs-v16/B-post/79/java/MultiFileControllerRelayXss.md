## Verdict

Exploitable. Untrusted user input (`authorName` and `comment` from request parameters) flows directly into HTML output without encoding, allowing arbitrary script injection.

## Source

**FeedbackController.java, lines 13 & 17:**
```java
String rawComment = request.getParameter("comment");
String authorName = request.getParameter("author");
```

Request parameters are user-controlled and untrusted.

## Fix

**FeedbackRenderer.java, add import:**
```java
import org.owasp.encoder.Encode;
```

**FeedbackRenderer.java, lines 28-31 (vulnerable code):**
```java
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
        + "<p>You said: " + submission.comment + "</p>"
        + "</body></html>";
```

**Fixed code:**
```java
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + Encode.forHtml(submission.authorName) + "!</h1>"
        + "<p>You said: " + Encode.forHtml(submission.comment) + "</p>"
        + "</body></html>";
```

## Explanation

The vulnerability exists because user-supplied `authorName` and `comment` values are concatenated directly into HTML without encoding. An attacker can inject script tags (e.g., `<script>alert('xss')</script>`) or event handlers (e.g., `<img src=x onerror="alert('xss')">`) that execute in the victim's browser. The fix applies context-appropriate HTML encoding using OWASP Java Encoder's `Encode.forHtml()` method at the output sink. This method encodes special characters (`<`, `>`, `&`, `"`, `'`) into HTML entities, rendering the injected content as literal text rather than executable code. The encoding is applied at the specific output point where data reaches the HTML body context, ensuring the rendered HTML is safe while legitimate content containing these characters continues to display correctly.

## Behaviour changes

None. The encoding transforms the data representation but does not alter the logical behaviour - HTML entities render as their original characters in the browser, so users see the intended text and feedback confirmation still displays correctly. The sink's contract (`response.getWriter().println()` writes HTML to the response) remains unchanged.
