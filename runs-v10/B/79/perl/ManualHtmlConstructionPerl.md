## Verdict

Confirmed. Untrusted user input is interpolated directly into HTML output without encoding, allowing XSS injection.

## Source

User-controlled data enters via `$cgi->param()` calls:
- Line 12: `$ticket_subject = $cgi->param('subject');`
- Line 13: `$customer_reply = $cgi->param('reply');`

These parameters flow directly into HTML string construction (lines 20-24) and are printed to the HTTP response at line 27.

## Fix

Import `HTML::Entities` and encode user input before using it in HTML output:

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

# Encode user input to prevent XSS
my $encoded_subject = encode_entities($ticket_subject);
my $encoded_reply   = encode_entities($customer_reply);

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $encoded_subject . "</h2>"
    . "<div class='reply'>" . $encoded_reply . "</div>"
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

The fix adds `use HTML::Entities;` to import the standard encoding function, then applies `encode_entities()` to both `$ticket_subject` and `$customer_reply` before including them in the HTML output. `encode_entities()` escapes HTML metacharacters (`<`, `>`, `&`, `"`, and `'`) so that user input is treated as data, not code. This prevents the browser from interpreting injected script tags or event handlers as executable JavaScript. The encoded values are stored in `$encoded_subject` and `$encoded_reply` and used in the HTML string instead of the raw parameters.

## Behaviour changes

- **Output encoding:** User input is now HTML-entity encoded before output. Characters like `<` become `&lt;`, `>` becomes `&gt;`, preventing script injection.
- **Display impact:** Legitimate content containing special characters (e.g., `"Q&A"`, `"3 < 5"`) renders correctly as escaped text rather than markup.
- **No functional change:** The ticket display, badge rendering, and HTTP response structure remain identical.
