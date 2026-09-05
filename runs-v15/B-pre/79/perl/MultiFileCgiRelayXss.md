## Verdict

Exploitable. Untrusted user input from the CGI request flows directly to HTML output without encoding, allowing arbitrary script injection.

## Source

`ticket_controller.pl` line 14: `my $subject = $cgi->param('subject');` retrieves untrusted input from the HTTP request. This value is passed through `TicketSummary->new()` at lines 19-22 and stored in the object's `subject` field without any sanitization or validation.

## Fix

**Vulnerable code (TicketPageRenderer.pm, line 19):**
```perl
say "<p>Subject: $subject</p>";
```

**Fixed code:**
```perl
use HTML::Entities;

sub render_confirmation {
    my ($summary) = @_;

    my $ticket_id = $summary->ticket_id;
    my $priority  = $summary->priority;
    my $subject   = $summary->subject;

    say "<html><body>";
    say "<h1>Ticket #$ticket_id filed</h1>";
    say "<p>Priority: $priority</p>";
    say "<p>Subject: " . encode_entities($subject) . "</p>";
    say "</body></html>";

    return;
}
```

## Explanation

The subject field contains untrusted user input that is rendered directly into HTML without encoding. An attacker can inject malicious payloads such as `<script>alert(1)</script>` or `" onmouseover="alert(1)` to execute arbitrary JavaScript in the victim's browser.

The fix applies `encode_entities()` from the `HTML::Entities` module (standard CPAN library, included with most Perl distributions) to encode the subject before output. This converts dangerous HTML metacharacters (`<`, `>`, `"`, `&`, and single quote) to their entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&amp;`, `&#039;`), ensuring the data is treated as text content rather than executable code. The `priority` field requires no encoding because it is validated against an allowlist in `_normalize_priority()`, constraining it to known safe values (low, normal, high, urgent), and `ticket_id` is auto-generated so it is trusted.

## Behaviour changes

None. HTML entity encoding preserves the display of all legitimate subject text. Users entering subjects containing special characters (e.g., "AT&T < Nokia" or 'Smith"s report') will see the text rendered correctly with those characters escaped in the HTML source, ensuring they display properly in the browser while preventing interpretation as HTML or script syntax.
