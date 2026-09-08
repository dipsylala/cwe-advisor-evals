## Verdict

The vulnerability is confirmed. Untrusted CGI parameters are directly embedded in HTML and printed without escaping, enabling XSS injection through the `subject` and `reply` parameters.

## Source

Lines 12-13 capture untrusted user input from CGI parameters:
- `$ticket_subject = $cgi->param('subject');`
- `$customer_reply = $cgi->param('reply');`

These values flow directly into HTML construction on lines 20-24 and are printed unescaped on line 27.

## Fix

### File: ManualHtmlConstructionPerl.pl

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities;

# Renders a single support ticket, including its subject line and the
# latest customer reply, as a small HTML fragment for the helpdesk UI.

my $cgi = CGI->new;

my $ticket_id      = $cgi->param('ticket_id');
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

print $cgi->header('text/html');
print "<html><head><title>Ticket View</title></head><body>\n";

my $status_badge = build_status_badge($ticket_id);

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print $ticket_html;

print "</body></html>\n";

sub build_status_badge {
    my ($id) = @_;
    return "<span class='badge'>Open</span>" if defined $id;
    return "<span class='badge'>Unknown</span>";
}
```

## Explanation

Added `use HTML::Entities;` to import the standard Perl HTML escaping function. Wrapped both user-supplied variables with `encode_entities()` on lines 21 and 22 where they are inserted into HTML. This converts special characters (`<`, `>`, `&`, `"`, etc.) to their HTML entity equivalents, preventing the browser from interpreting them as markup or script tags. An attacker's payload like `<script>alert('XSS')</script>` becomes `&lt;script&gt;alert('XSS')&lt;/script&gt;` and renders as plain text instead of executing.
