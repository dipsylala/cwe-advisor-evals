## Verdict
CONFIRMED. CWE-79 (Cross-site Scripting) via unescaped user input in HTML output.

## Source
**File:** `TicketPageRenderer.pm` line 19  
**Call chain:** `ticket_controller.pl` receives untrusted `subject` parameter from CGI request → passes to `TicketSummary->new()` → retrieved and rendered in `render_confirmation()` → directly interpolated into HTML without escaping.

**Vulnerability:** The `$subject` variable, sourced from user input, is concatenated into HTML output without escaping. An attacker can submit a subject containing `<script>` tags or event handlers that execute in the victim's browser.

## Fix
In `TicketPageRenderer.pm`, import the HTML escaping function and escape the subject before rendering:

```perl
package TicketPageRenderer;
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
    say "<p>Priority: $priority</p>";
    say "<p>Subject: " . escapeHTML($subject) . "</p>";
    say "</body></html>";

    return;
}

1;
```

**Key change:** Line 19 becomes `say "<p>Subject: " . escapeHTML($subject) . "</p>";` with `use CGI qw(escapeHTML);` added to imports.

## Explanation
The `$priority` field is already safe because `TicketSummary::_normalize_priority()` constrains it to a known allowlist of values (low, normal, high, urgent), but `$subject` is free-text user input that passes through untouched.

`CGI::escapeHTML()` converts HTML metacharacters to entities (`<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`), preventing the browser from interpreting the content as HTML markup or JavaScript. This is the standard defense-in-depth approach for rendering untrusted data in HTML context.
