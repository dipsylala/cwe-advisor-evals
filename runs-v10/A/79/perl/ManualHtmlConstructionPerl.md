## Verdict

CWE-79 confirmed. User-controlled input (`$ticket_subject` and `$customer_reply`) is concatenated directly into HTML without escaping, allowing arbitrary HTML and JavaScript injection when printed at line 27.

## Source

Request parameters:
- `$cgi->param('subject')` assigned to `$ticket_subject` (line 12)
- `$cgi->param('reply')` assigned to `$customer_reply` (line 13)

Both are embedded unescaped into the `$ticket_html` string (lines 21–22).

## Fix

Use `CGI::escapeHTML()` to encode user-controlled values before embedding them in HTML:

```perl
use CGI qw(escapeHTML);

# ... existing code ...

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . escapeHTML($ticket_subject) . "</h2>"
    . "<div class='reply'>" . escapeHTML($customer_reply) . "</div>"
    . $status_badge
    . "</div>";
```

Import `escapeHTML` from the `CGI` module at the top (already `use CGI` is present), then wrap each user-supplied variable with `escapeHTML()` before string interpolation.

## Explanation

`escapeHTML()` converts dangerous characters (`<`, `>`, `"`, `&`) into HTML entities (`&lt;`, `&gt;`, `&quot;`, `&amp;`), preventing the browser from interpreting user input as markup or script. This ensures that malicious payloads like `<script>alert('xss')</script>` are rendered as literal text rather than executed. Since `CGI` is already imported, no additional dependencies are required.
