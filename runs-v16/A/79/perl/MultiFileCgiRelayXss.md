## Verdict

Confirmed XSS vulnerability. The `$subject` variable contains untrusted user input from a CGI parameter that flows through TicketSummary unchanged and is output directly into HTML at line 19 of TicketPageRenderer.pm without any escaping. An attacker can inject JavaScript code through the subject parameter, which will execute in the browser of users viewing the confirmation page.

## Source

**TicketPageRenderer.pm, line 19:**
```perl
say "<p>Subject: $subject</p>";
```

The `$subject` variable is derived from the CGI parameter `subject` (ticket_controller.pl line 14), passed through TicketSummary unchanged (TicketSummary.pm line 14), and then interpolated directly into HTML output without escaping.

## Fix

**TicketPageRenderer.pm:**

```perl
package TicketPageRenderer;
# Renders the confirmation page shown to the requester after a ticket
# is filed, using the summary object assembled by TicketSummary.
use strict;
use warnings;
use feature 'say';
use CGI qw(escapeHTML);

sub render_confirmation {
    my ($summary) = @_;

    my $ticket_id = $summary->ticket_id;
    my $priority  = $summary->priority;
    my $subject   = $summary->subject;

    say "<html><body>";
    say "<h1>Ticket #$ticket_id filed</h1>";
    say "<p>Priority: " . escapeHTML($priority) . "</p>";
    say "<p>Subject: " . escapeHTML($subject) . "</p>";
    say "</body></html>";

    return;
}

1;
```

The fix adds `use CGI qw(escapeHTML);` and wraps both `$priority` and `$subject` with `escapeHTML()` before output.

## Explanation

The vulnerability exists because user-supplied input flows directly from the CGI parameter into HTML output without neutralization. When `say "<p>Subject: $subject</p>";` is executed with a subject like `<script>alert('XSS')</script>`, the browser parses the HTML and executes the injected script.

The fix uses `CGI::escapeHTML()` to convert HTML special characters (`<`, `>`, `&`, `"`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`). This prevents the browser from interpreting user input as HTML markup or JavaScript code. While `$priority` is normalized to one of a known set of values in TicketSummary, escaping it as well follows defense-in-depth principles and ensures the rendering layer is robust regardless of upstream validation.
