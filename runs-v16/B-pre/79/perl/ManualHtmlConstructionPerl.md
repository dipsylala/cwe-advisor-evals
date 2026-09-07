## Verdict

VULNERABLE. The code constructs an HTML string by directly interpolating `$ticket_subject` and `$customer_reply` (obtained from CGI parameters) without encoding at lines 20-24. These values are then printed to the browser at line 27, allowing an attacker to inject arbitrary HTML and JavaScript via the CGI parameters.

## Source

User input enters the application at lines 11-13 via `$cgi->param()`:
- `$ticket_subject` from the `subject` parameter
- `$customer_reply` from the `reply` parameter

Both parameters are untrusted and come directly from the HTTP request.

## Fix

Import `HTML::Entities` and encode both user-controlled values before inserting them into the HTML string:

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

# HTML-encode user input for safe output
my $encoded_subject = encode_entities($ticket_subject);
my $encoded_reply   = encode_entities($customer_reply);

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $encoded_subject . "</h2>"
    . "<div class='reply'>" . $encoded_reply . "</div>"
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

The vulnerability exists because the code treats untrusted HTTP parameter values as safe HTML content. An attacker can supply values like `<script>alert(1)</script>` or `" onmouseover="alert(1)` that execute in the victim's browser.

The fix applies HTML entity encoding to both `$ticket_subject` and `$customer_reply` before they are incorporated into the HTML string. `HTML::Entities::encode_entities()` converts dangerous characters (`<`, `>`, `&`, `"`) and single quotes into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing them from being interpreted as markup or attribute delimiters.

This encoding is applied at the output sink (where data is rendered to HTML), which is the primary defence against XSS. It renders all injected payloads inert by ensuring user input remains data, never code.

## Behaviour changes

- XSS payloads in the `subject` and `reply` parameters are rendered as escaped text rather than executed code: `<script>alert(1)</script>` appears as `&lt;script&gt;alert(1)&lt;/script&gt;` in the HTML
- Legitimate content containing `<`, `>`, `&`, or quotes is correctly encoded and displays as intended
- The HTML structure remains unchanged; only the data is escaped
- The encoding is transparent to users; they see the intended subject and reply text in their browser
