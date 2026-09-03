## Verdict
CONFIRMED: Cross-site scripting via unsanitized user input embedded in HTML output.

## Source
Lines 21–22 embed CGI parameters `$ticket_subject` and `$customer_reply` directly into an HTML string without escaping:
```
"<h2>" . $ticket_subject . "</h2>"
"<div class='reply'>" . $customer_reply . "</div>"
```

Both parameters originate from untrusted user input via `$cgi->param()` (lines 12–13). An attacker can inject JavaScript by crafting a malicious `subject` or `reply` parameter containing HTML entities or script tags.

## Fix
Escape HTML special characters in user-supplied values before embedding them in the HTML output:

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;

my $ticket_id      = $cgi->param('ticket_id');
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

print $cgi->header('text/html');
print "<html><head><title>Ticket View</title></head><body>\n";

my $status_badge = build_status_badge($ticket_id);

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $cgi->escapeHtml($ticket_subject) . "</h2>"
    . "<div class='reply'>" . $cgi->escapeHtml($customer_reply) . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;

print "</body></html>\n";

sub build_status_badge {
    my ($id) = @_;
    return "<span class='badge'>Open</span>" if defined $id;
    return "<span class='badge'>Unknown</span>";
}
```

## Explanation
The CGI module provides `escapeHtml()`, a built-in method that converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their entity forms (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This prevents the browser from interpreting injected markup or scripts as executable code. By calling `$cgi->escapeHtml()` on both `$ticket_subject` and `$customer_reply` before concatenating them into the HTML string (lines 21–22), the script neutralizes the XSS vector while preserving the intended text content.
