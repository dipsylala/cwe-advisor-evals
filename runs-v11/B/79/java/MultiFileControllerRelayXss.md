## Verdict

**Exploitable.** Untrusted user input (`submission.authorName` and `submission.comment`) flows directly into an HTML page without encoding. An attacker can inject JavaScript or HTML that executes in the victim's browser. For example, input like `"><script>alert('xss')</script><p class="` will be rendered as executable HTML.

## Source

The FeedbackSubmission object holds two user-controlled fields:
- `authorName` - provided by the user submitting feedback
- `comment` - provided by the user submitting feedback

These are concatenated directly into an HTML string on lines 28-31 without any output encoding.

## Fix

Add the OWASP Java Encoder dependency and apply `Encode.forHtml()` to both untrusted fields:

**Step 1: Add import**
```
import org.owasp.encoder.Encode;
```

**Step 2: Apply encoding at the point of HTML construction (lines 28-31)**

Replace:
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

The OWASP Java Encoder library is maintained and widely used; confirm the current version via your SCA tooling or Maven Central before merging.

## Explanation

`Encode.forHtml()` converts characters that have special meaning in HTML (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that user input is always treated as text content, never as HTML structure or script code. When the response is rendered, the browser interprets the entities and displays the original text to the user without executing any injected code. The fix applies context-specific encoding (HTML entity encoding for HTML body text) at the exact point where untrusted data is included in the HTML string, which is the standard pattern for preventing XSS in Java servlet responses.

## Behaviour changes

**Before**: User input containing characters like `<`, `>`, or quotes would be rendered as HTML markup. Input like `<script>alert(1)</script>` would execute; input like `"><img src=x onerror=alert(1)>` would break out of the element and inject an event handler.

**After**: The same input is safely rendered as visible text. `<script>alert(1)</script>` displays literally as the string `<script>alert(1)</script>`. The HTML structure remains intact and injection is impossible.

**Legitimate content handling**: Text containing `<`, `>`, `&`, quotes, or other special characters now displays correctly as the intended text rather than being interpreted as HTML. For example, user input like "I love C++ & Java" renders as intended text, not as broken HTML.

**No functional changes**: The response structure, HTTP headers, and user experience remain identical—only the output encoding changes.
