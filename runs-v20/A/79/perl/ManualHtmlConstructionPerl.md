## Verdict

Confirmed. `$ticket_subject` and `$customer_reply` are read directly from request
parameters (`$cgi->param('subject')`, `$cgi->param('reply')`) and concatenated
verbatim into an HTML string that is written to the response with no encoding at
any point between source and sink, allowing stored/reflected script injection via
either parameter (e.g. `subject=<script>...</script>`).

## Source

- `E:/Github/cwe-advisor/evals/cases/79/perl/ManualHtmlConstructionPerl/ManualHtmlConstructionPerl.pl:12` - `my $ticket_subject = $cgi->param('subject');`
- `E:/Github/cwe-advisor/evals/cases/79/perl/ManualHtmlConstructionPerl/ManualHtmlConstructionPerl.pl:13` - `my $customer_reply = $cgi->param('reply');`

Both flow unmodified into the `$ticket_html` string built at lines 20-24 and printed
at line 27 (the reported sink).

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

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $cgi->escapeHTML($ticket_subject) . "</h2>"
    . "<div class='reply'>" . $cgi->escapeHTML($customer_reply) . "</div>"
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

`CGI.pm`'s `escapeHTML` method (available on the existing `$cgi` object, so no new
dependency is introduced) HTML-entity-encodes the five characters that let attacker
input break out of text content or attribute context: `<`, `>`, `&`, `"`, and `'`.
Applying it to `$ticket_subject` and `$customer_reply` at the point they are
concatenated into the markup neutralizes any HTML/script markup those parameters
contain while leaving the literal text of a legitimate subject line or reply intact,
so `<script>alert(1)</script>` is rendered as inert text inside the `<h2>`/`<div>`
rather than executed. `$status_badge` and `$ticket_id` are not attacker-controlled
markup (the function only ever returns one of two fixed literal strings, only
checking whether `$ticket_id` is defined) and are left untouched, since escaping a
value that never fails the plausibility check is not a real fix.
