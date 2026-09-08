## Verdict

Confirmed. `TicketPageRenderer::render_confirmation` interpolates `$summary->subject` directly into the HTML response body without any output encoding. That value originates as `$cgi->param('subject')` in `ticket_controller.pl` - an untrusted, free-text request parameter - and passes through `TicketSummary::new` unchanged (only `priority` is normalized against an allowlist; `subject` is stored verbatim). A requester-supplied subject line such as `<script>...</script>` or an `onerror`-bearing tag is written straight into the page markup and executes in the browser of whoever views the confirmation page, giving reflected/stored XSS depending on where the summary is persisted or redisplayed.

## Source

`ticket_controller.pl`, line 14: `my $subject = $cgi->param('subject');` - an untrusted CGI request parameter, carried unmodified through `TicketSummary->new(subject => $subject, ...)` into `$self->{subject}`, and read back out via `TicketSummary::subject` at `TicketPageRenderer.pm` line 13.

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
    say "<h1>Ticket #" . escapeHTML($ticket_id) . " filed</h1>";
    say "<p>Priority: " . escapeHTML($priority) . "</p>";
    say "<p>Subject: " . escapeHTML($subject) . "</p>";
    say "</body></html>";

    return;
}

1;
```

## Explanation

The fix HTML-encodes every dynamic value at the point it is written into the response, using `CGI::escapeHTML` (already an implicit dependency of this application via `ticket_controller.pl`, so no new package is introduced). `escapeHTML` converts `<`, `>`, `&`, `"` and `'` to their entity forms, so a subject line containing markup renders as inert text instead of being parsed as HTML/script by the browser.

`subject` is the actual attacker-controlled field and is the value the finding points at, but `ticket_id` and `priority` are also encoded for consistency and defense-in-depth: `ticket_id` is an internal auto-incrementing integer and `priority` is constrained by `TicketSummary::_normalize_priority` to a fixed allowlist (`low`, `normal`, `high`, `urgent`), so escaping them is a no-op for legitimate values and does not change the rendered output - it only removes the risk if either field's provenance changes later (e.g. `ticket_id` becomes a non-numeric external identifier). The fix stays entirely inside the rendering function, which is the correct place to neutralize output regardless of how many call sites eventually feed it data, rather than trying to sanitize at every point upstream that constructs a `TicketSummary`.

No allowlist or input-side stripping was applied to `subject`: it is free-text the requester is entitled to enter (a ticket subject line), so rejecting or mutating characters like `<` would be a product regression. Encoding at the output sink is the correct, non-lossy defense here - the stored/passed value is unchanged, only its rendering into HTML is made safe.
