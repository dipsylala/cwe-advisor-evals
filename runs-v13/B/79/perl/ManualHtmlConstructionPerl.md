## Verdict

**VULNERABLE** — Confirmed XSS via unencoded user input rendered directly into HTML output.

## Source

Two attacker-controlled sources flow to the sink without encoding:

- `$cgi->param('subject')` (line 12) — ticket subject parameter
- `$cgi->param('reply')` (line 13) — customer reply parameter

Both are embedded directly into the HTML string at lines 20–22.

## Fix

Add `use HTML::Entities;` to imports (after line 3), then apply `encode_entities()` to both user inputs when building the HTML:

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

print $ticket_html;

print "</body></html>\n";

sub build_status_badge {
    my ($id) = @_;
    return "<span class='badge'>Open</span>" if defined $id;
    return "<span class='badge'>Unknown</span>";
}
```

## Explanation

The vulnerability occurs because user-supplied `$ticket_subject` and `$customer_reply` parameters are concatenated directly into HTML output without escaping special characters. An attacker can inject `<script>` tags or event-handler attributes to execute arbitrary JavaScript in the victim's browser.

The fix applies HTML entity encoding via `HTML::Entities::encode_entities()` to both sources immediately before embedding them in the output. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring they are rendered as literal text rather than interpreted as HTML or script code. This encoding is applied at the output sink (the string construction), following the principle of context-aware encoding at each rendering point.

## Behaviour changes

- **Special characters in user input are now escaped**: User-provided text containing `<`, `>`, `&`, quotes, or other HTML metacharacters will be rendered as safe literal text (e.g., "User's Reply" displays correctly; `<img src=x onerror=alert(1)>` displays as visible text, not an image element).
- **XSS payloads are neutralized**: Attack attempts like `<script>alert('XSS')</script>` or `<img onerror=alert(1)>` render as visible text rather than executing.
- **Legitimate HTML-like content displays safely**: If a customer reply contains text like "Cost: <100" or "Use & symbols", these now display correctly escaped instead of breaking the page layout.
