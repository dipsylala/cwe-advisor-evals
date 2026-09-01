## Verdict

Confirmed: The untrusted `subject` parameter flows from the CGI input through the TicketSummary domain object to the TicketPageRenderer sink without HTML encoding, allowing an attacker to inject arbitrary JavaScript that executes in the victim's browser.

## Source

**File**: ticket_controller.pl, line 14
**Code**: `my $subject = $cgi->param('subject');`

The `subject` parameter is extracted directly from the CGI request with no validation or sanitization.

## Fix

**File**: TicketPageRenderer.pm

**Vulnerable Code**:
```perl
use strict;
use warnings;
use feature 'say';

sub render_confirmation {
    my ($summary) = @_;

    my $ticket_id = $summary->ticket_id;
    my $priority  = $summary->priority;
    my $subject   = $summary->subject;

    say "<html><body>";
    say "<h1>Ticket #$ticket_id filed</h1>";
    say "<p>Priority: $priority</p>";
    say "<p>Subject: $subject</p>";
    say "</body></html>";

    return;
}
```

**Fixed Code**:
```perl
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
    say "<p>Subject: " . encode_entities($subject) . "</p>";
    say "</body></html>";

    return;
}
```

## Explanation

The fix applies HTML entity encoding at the output sink using `HTML::Entities::encode_entities()`. This function converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing injected script tags and event handlers from being interpreted as code. The encoding is applied only at the rendering point where the untrusted subject is output to HTML, preserving the original value in the domain object for other potential use cases (logging, storage, etc.) while ensuring safe display in the web response.

## Behaviour changes

The subject line output now displays HTML entity-encoded text. User input containing special characters will render literally:
- Input: `Test <script>alert(1)</script>`
- Before fix: Script executes in browser (XSS)
- After fix: Displays as text: `Test &lt;script&gt;alert(1)&lt;/script&gt;`

This is the intended behaviour - all input is treated as data, not markup.
