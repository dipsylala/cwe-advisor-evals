## Verdict
Confirmed: Cross-site Scripting (CWE-79) via unsanitized user input.

## Source
The vulnerability originates on lines 11-13, where untrusted input is obtained from CGI parameters:
- `$ticket_subject` and `$customer_reply` are user-supplied values from HTTP request parameters

Lines 20-24 embed this unsanitized input directly into an HTML string, and line 27 prints this HTML to the response without escaping the embedded values. An attacker can inject malicious HTML/JavaScript that will execute in the browser of any user viewing the ticket.

## Fix

### File: ManualHtmlConstructionPerl.pl

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;

# Renders a single support ticket, including its subject line and the
# latest customer reply, as a small HTML fragment for the helpdesk UI.

my $cgi = CGI->new;

my $ticket_id      = $cgi->param('ticket_id');
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

print $cgi->header('text/html');
print "<html><head><title>Ticket View</title></head><body>\n";

my $status_badge = build_status_badge($ticket_id);

my $escaped_subject = CGI::escapeHTML($ticket_subject);
my $escaped_reply   = CGI::escapeHTML($customer_reply);

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $escaped_subject . "</h2>"
    . "<div class='reply'>" . $escaped_reply . "</div>"
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
The fix applies HTML entity encoding using `CGI::escapeHTML()` to all user-supplied input before embedding it in the HTML output. This function converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting them as markup or JavaScript.

The escaping is applied to `$ticket_subject` and `$customer_reply` on lines 20-21, and the escaped values are then used in the HTML string construction on lines 23-27. This ensures that any special characters in user input are rendered as literal text rather than executable code or markup.
