## Verdict

**Confirmed.** Untrusted user input from `$cgi->param('subject')` and `$cgi->param('reply')` is directly interpolated into HTML output without encoding, creating an exploitable XSS vulnerability in the HTML body context. An attacker can inject `<script>` tags or event handlers through either parameter.

## Source

Lines 11-13 retrieve untrusted CGI parameters. Lines 21-22 interpolate `$ticket_subject` and `$customer_reply` directly into HTML via string concatenation. Line 27 prints the unencoded HTML to the HTTP response.

**Vulnerable code:**
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

## Fix

Import `HTML::Entities` and apply `encode_entities()` to both user-controlled variables before rendering them into HTML:

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities qw(encode_entities);

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

`HTML::Entities::encode_entities()` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entity references (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This ensures that user input is treated as data, not executable code. When applied to both `$ticket_subject` and `$customer_reply` before rendering, it prevents any injected `<script>` tags, event handlers, or other HTML markup from executing. The function is applied at the output sink (where data enters the HTTP response), which is the correct location for context-specific encoding.

## Behaviour changes

**Input with special characters now renders safely:**
- Input: `subject="<script>alert(1)</script>"`
- Before fix: Injects executable script into the page
- After fix: Renders as literal text: `&lt;script&gt;alert(1)&lt;/script&gt;`

**Legitimate content with ampersands or quotes still renders correctly:**
- Input: `reply="Quotes & code examples: if (x < 5) { ... }"`
- Before fix: Breaks HTML parsing; `<` could start a tag
- After fix: Renders as: `Quotes &amp; code examples: if (x &lt; 5) { ... }`

**Output context remains unchanged:**
- Still prints to HTTP response via `print $ticket_html`
- Still produces valid HTML to the browser
- User data remains in HTML body context (not JavaScript, CSS, or URL context)
