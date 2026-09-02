## Verdict

exploitable (confidence: high)

- cwe_id: CWE-79
- location: `TicketPageRenderer.pm`, line 19 (sink); source at `ticket_controller.pl`, line 14

## Source

`$cgi->param('subject')` in `ticket_controller.pl` (line 14) reads the requester-supplied ticket subject directly from the CGI request. It flows unmodified into `TicketSummary->new(subject => $subject, ...)` (line 19-22), where `TicketSummary::new` stores it verbatim as `$self->{subject}` (`TicketSummary.pm`, line 14) - the comment on line 21-22 of that file confirms "the subject line passes through untouched - it is free-text the requester typed." The accessor `subject()` (line 29) returns it unchanged. `TicketPageRenderer::render_confirmation` retrieves it via `$summary->subject` (line 13) and interpolates it directly into HTML output at the `say "<p>Subject: $subject</p>";` statement (line 19), which is the sink flagged by the finding. No HTML encoding occurs anywhere along this path.

By contrast, `priority` is constrained by `TicketSummary::_normalize_priority`, which checks the raw value against an allowlist (`qw(low normal high urgent)`) and substitutes the canonical allowlisted value (or `'normal'`) rather than passing the tainted input through - that field is not exploitable and needs no change.

## Fix

Vulnerable code (`TicketPageRenderer.pm`):

```perl
package TicketPageRenderer;
# Renders the confirmation page shown to the requester after a ticket
# is filed, using the summary object assembled by TicketSummary.
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
    # VULNERABLE: $subject is untrusted, attacker-controlled free text
    # rendered into HTML with no encoding.
    say "<p>Subject: $subject</p>";
    say "</body></html>";

    return;
}

1;
```

Fixed code (`TicketPageRenderer.pm`):

```perl
package TicketPageRenderer;
# Renders the confirmation page shown to the requester after a ticket
# is filed, using the summary object assembled by TicketSummary.
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

- library_recommendation: `HTML::Entities` (core-distributed with Perl; ships as part of the `HTML-Parser` CPAN distribution). The knowledge base carries no minimum safe version for this function - confirm the resolved version against SCA/dependency-check tooling before merging rather than pinning one from recall.

## Explanation

The fix HTML-encodes `$subject` with `HTML::Entities::encode_entities()` at the point it is read from the domain object, immediately before it is used in the `say` statements that build the HTML response - the same rendering function that contains the flagged sink. This turns any `<`, `>`, `&`, or quote characters in the attacker-supplied subject line into their HTML entity equivalents, so a payload such as `<script>alert(1)</script>` renders as inert text in the `<p>` element instead of being parsed as markup or script by the browser, closing the reflected-XSS weakness while leaving legitimate subjects containing those characters displayed correctly (as their literal characters, not executed).

## Behaviour changes

Legitimate subject text containing `<`, `>`, `&`, or quote characters will now render as HTML entities (e.g. `&lt;`) instead of being passed through as raw markup - this is the intended effect of closing the injection, not a side effect, since the original behavior of rendering those characters as HTML was the vulnerability. `ticket_id` and `priority` are untouched: `priority` was already restricted to a server-controlled allowlist value before reaching this function and requires no encoding, and `ticket_id` is an internal integer counter, not attacker-controlled input. No arguments, return values, or control flow changed beyond the one added encoding call.
