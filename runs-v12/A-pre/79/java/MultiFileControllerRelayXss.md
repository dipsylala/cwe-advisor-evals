## Verdict

The vulnerability is confirmed. User-controlled input from HTTP request parameters (`author` and `comment`) flows through `FeedbackController.handleSubmit()` into `FeedbackRenderer.renderConfirmation()`, where both values are concatenated directly into an HTML string and written to the response without HTML encoding. An attacker can inject arbitrary HTML/JavaScript that will execute in the victim's browser.

## Source

**File:** FeedbackRenderer.java  
**Line:** 29-30 (where user input is concatenated into HTML)  
**Sink:** Line 36 (`out.println(html)`)  
**Data Flow:** 
- `FeedbackController.handleSubmit()` receives `request.getParameter("author")` and `request.getParameter("comment")` from HTTP request
- These are passed directly to `FeedbackRenderer.FeedbackSubmission` constructor
- `FeedbackRenderer.renderConfirmation()` concatenates these unescaped values into an HTML string
- The string is output via `out.println(html)` to the HTTP response

## Fix

Import Apache Commons Text at the top of FeedbackRenderer.java:
```java
import org.apache.commons.text.StringEscapeUtils;
```

Replace the HTML construction in the `renderConfirmation()` method (lines 28-31):

**Before:**
```java
String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + submission.authorName + "!</h1>"
        + "<p>You said: " + submission.comment + "</p>"
        + "</body></html>";
```

**After:**
```java
String escapedAuthorName = StringEscapeUtils.escapeHtml4(submission.authorName);
String escapedComment = StringEscapeUtils.escapeHtml4(submission.comment);

String html = "<html><body>"
        + "<h1>Thanks for your feedback, " + escapedAuthorName + "!</h1>"
        + "<p>You said: " + escapedComment + "</p>"
        + "</body></html>";
```

## Explanation

The fix applies HTML entity encoding to both user-supplied fields before inserting them into the HTML response. `StringEscapeUtils.escapeHtml4()` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their corresponding HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This prevents the browser from interpreting injected content as executable code or markup.

For example, if an attacker submits `author=<script>alert('XSS')</script>`, the escaped value becomes `&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;`, which renders as literal text in the HTML output instead of executing as JavaScript.

Apache Commons Text (`org.apache.commons:commons-text`) is a well-maintained library widely used in Java web applications for this purpose. It provides robust HTML encoding that correctly handles all HTML4 entities.
