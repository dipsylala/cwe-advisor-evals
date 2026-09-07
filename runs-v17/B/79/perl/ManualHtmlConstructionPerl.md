## Verdict

The finding is valid. Untrusted CGI parameters (`subject`, `reply`) are concatenated into HTML without encoding and then rendered directly to output on line 27. This allows an attacker to inject arbitrary HTML/JavaScript into the page.

## Source

Lines 11-13 extract untrusted data from CGI parameters:
```
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');
```

Lines 20-24 concatenate these values directly into HTML without encoding:
```
my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"
    . "<div class='reply'>" . $customer_reply . "</div>"
    . $status_badge
    . "</div>";
```

Line 27 outputs the unencoded HTML:
```
print $ticket_html;
```

An attacker can supply `subject=<img src=x onerror=alert(1)>` to execute arbitrary JavaScript in the context of any helpdesk user's browser.

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

The fix adds `use HTML::Entities` at the top and wraps the untrusted values with `encode_entities()` on lines 21 and 22. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring they are rendered as text rather than executed as markup. With this encoding, an attacker's payload `<img src=x onerror=alert(1)>` becomes the literal string `&lt;img src=x onerror=alert(1)&gt;`, which the browser displays as text and does not execute. The `build_status_badge()` function output is not encoded because it contains only hardcoded HTML strings under application control.

## Behaviour changes

- User-supplied content containing `<`, `>`, `&`, `"`, or `'` characters will now be displayed as literal text rather than interpreted as HTML markup.
- This preserves the intended functionality (displaying ticket subjects and replies as content) while preventing XSS injection.
- No legitimate functionality is broken; only attack payloads are neutralized.
- The page continues to render with proper styling and structure, as `encode_entities()` only escapes content characters and leaves HTML tags in the application's own markup untouched.

