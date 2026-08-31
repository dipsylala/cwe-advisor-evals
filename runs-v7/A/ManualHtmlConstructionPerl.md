## Verdict
The code directly concatenates untrusted user input (`$ticket_subject` and `$customer_reply`) into HTML without escaping, creating a reflected XSS vulnerability at line 27 when the unsanitized `$ticket_html` is printed to output.

## Source
```perl
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"
    . "<div class='reply'>" . $customer_reply . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;
```

Attacker-controlled parameters are embedded directly into HTML context without neutralization.

## Fix
```perl
use CGI qw(:standard);

my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . escapeHTML($ticket_subject) . "</h2>"
    . "<div class='reply'>" . escapeHTML($customer_reply) . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;
```

Apply `escapeHTML()` to each user-supplied variable before inserting it into the HTML string. This converts special characters (`<`, `>`, `"`, `&`) to their HTML entity equivalents, preventing injected script tags or event handlers from being interpreted as code.

## Explanation
The `CGI::escapeHTML()` function (imported via `use CGI qw(:standard)`) neutralizes XSS by encoding HTML metacharacters. When `$ticket_subject` contains `<script>alert('xss')</script>`, it becomes `&lt;script&gt;alert('xss')&lt;/script&gt;`, which renders as literal text rather than executing as code. Apply this to all user-controlled values that flow into HTML output.
