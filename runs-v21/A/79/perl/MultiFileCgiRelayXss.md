## Verdict
Fixed. The subject variable is output directly to HTML without escaping, allowing script injection. Escaping the variable with CGI::escapeHTML before output prevents the vulnerability.

## Source
The vulnerability is a reflected XSS where untrusted user input from the `subject` CGI parameter flows through TicketSummary.pm unchanged and is rendered in HTML output by TicketPageRenderer.pm at line 19 without HTML entity escaping. An attacker can inject JavaScript via the subject parameter, which executes in the browser of the ticket requester.

## Fix

### File: TicketPageRenderer.pm

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
    say "<p>Priority: $priority</p>";
    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    say "<p>Subject: " . escapeHTML($subject) . "</p>";
    say "</body></html>";

    return;
}

1;
```

## Explanation
The fix adds `use CGI qw(escapeHTML);` to import the escapeHTML function from the CGI module (already a dependency of the codebase). At the XSS sink (line 19, now line 20 with the added import), the subject variable is wrapped with `escapeHTML()` before concatenation into the HTML string. This converts HTML special characters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the injected script from being parsed as code. The priority and ticket_id fields are not escaped because priority is already constrained to a known whitelist via normalization, and ticket_id is a server-generated integer.
