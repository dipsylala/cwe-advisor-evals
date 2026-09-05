## Verdict

Exploitable.

## Source

`$cgi->param('subject')` in ticket_controller.pl - untrusted user-supplied text from a CGI request parameter, passed through a TicketSummary domain object to the renderer without validation or encoding.

## Fix

**Vulnerable code (line 19):**
```perl
    say "<p>Subject: $subject</p>";
```

**Fixed code:**
```perl
use HTML::Entities qw(encode_entities);
...
    say "<p>Subject: " . encode_entities($subject) . "</p>";
```

## Explanation

The vulnerability occurs because `$subject` is interpolated directly into HTML output without encoding. An attacker can provide a subject containing `<script>alert(1)</script>` or event-handler markup like `onmouseover=` and the browser will execute it. The fix applies HTML entity encoding via `HTML::Entities::encode_entities()` at the output sink, converting special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents so they are rendered as text, not code. This is the context-appropriate encoding for HTML body and attribute text contexts, preventing XSS injection while preserving the legitimate subject text for display.

## Behaviour changes

None. The `encode_entities()` function returns a string with special HTML characters escaped; it preserves all the original text and does not alter the return contract or arguments of the `say` call. The output remains valid HTML content rendered safely.
