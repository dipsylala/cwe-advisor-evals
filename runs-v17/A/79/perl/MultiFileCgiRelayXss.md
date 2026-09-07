## Verdict
VULNERABLE. The `subject` parameter flows from untrusted CGI input through the domain object into HTML output without escaping, enabling script injection.

## Source
`ticket_controller.pl`: Line 14 acquires untrusted `subject` from CGI parameter `$cgi->param('subject')`.

## Fix

### File: TicketPageRenderer.pm
```perl
package TicketPageRenderer;
# Renders the confirmation page shown to the requester after a ticket
# is filed, using the summary object assembled by TicketSummary.
use strict;
use warnings;
use feature 'say';
use HTML::Entities;

sub render_confirmation {
    my ($summary) = @_;

    my $ticket_id = $summary->ticket_id;
    my $priority  = $summary->priority;
    my $subject   = $summary->subject;

    say "<html><body>";
    say "<h1>Ticket #$ticket_id filed</h1>";
    say "<p>Priority: $priority</p>";
    # Subject escaped to prevent XSS injection into HTML context
    say "<p>Subject: " . encode_entities($subject) . "</p>";
    say "</body></html>";

    return;
}

1;
```

## Explanation
The vulnerability occurs because `$subject` (untrusted user input) is interpolated directly into HTML at line 19 without escaping. An attacker can inject JavaScript via the subject field: `<script>alert(1)</script>`.

The fix imports `HTML::Entities` and wraps the subject with `encode_entities()`, which converts `<`, `>`, `&`, and `"` to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`). This prevents the browser from interpreting injected markup as code while preserving the readable output. The `priority` field is safe because `_normalize_priority()` in TicketSummary.pm constrains it to a known set of values (low, normal, high, urgent).
