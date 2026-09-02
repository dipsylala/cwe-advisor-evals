## Verdict

Real vulnerability. Untrusted user input flows unencoded from the web form through to HTML output without any sanitization or encoding.

## Source

**ticket_controller.pl, line 14:** `my $subject = $cgi->param('subject');`

This retrieves untrusted user input directly from the HTTP request. The subject is free-text provided by the requester with no validation, as documented in the TicketSummary comments ("passes through untouched").

## Fix

Add `use HTML::Entities;` to TicketPageRenderer.pm and apply HTML entity encoding at the output sink:

**TicketPageRenderer.pm - Updated code:**

```perl
package TicketPageRenderer;
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
    say "<p>Subject: " . HTML::Entities::encode_entities($subject) . "</p>";
    say "</body></html>";

    return;
}

1;
```

## Explanation

The vulnerability exists because untrusted user input from `$cgi->param('subject')` travels unmodified through the TicketSummary domain object and is rendered directly into HTML via string interpolation in line 19. An attacker can submit a subject containing XSS payloads like `<script>alert('XSS')</script>` which will be included as-is in the HTML output and executed in the victim's browser.

The fix applies HTML entity encoding at the output sink using `HTML::Entities::encode_entities()`. This encodes special HTML characters (`<`, `>`, `&`, `"`, `'`) into their entity representations (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting injected markup or script tags as code. The encoding is applied only at the point of HTML output, which is the correct location per the CWE-79 principle of context-aware output encoding at each sink.

## Behaviour changes

- Characters with HTML significance (`<`, `>`, `&`, `"`, `'`) in the subject line are now rendered as HTML entities rather than raw characters.
- A subject like `<script>alert(1)</script>` is displayed as the literal text `&lt;script&gt;alert(1)&lt;/script&gt;` rather than being interpreted as executable code.
- Legitimate subject content containing these characters (e.g., URLs with `&`, mathematical expressions with `<>`), will render with entities visible in the HTML source but displayed correctly to the user as the original characters.
- The ticket ID and priority are not affected; they remain unencoded where appropriate (ticket_id is numeric and priority is constrained to a known set via allowlist in TicketSummary::_normalize_priority).
