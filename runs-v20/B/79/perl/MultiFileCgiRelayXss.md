## Verdict

exploitable

- cwe_id: CWE-79
- location: TicketPageRenderer.pm, line 19 (`say "<p>Subject: $subject</p>";`)
- confidence: high

## Source

`ticket_controller.pl` reads the untrusted CGI parameter `my $subject = $cgi->param('subject');` and passes it unmodified into `TicketSummary->new(subject => $subject, ...)`. `TicketSummary::new` stores it verbatim in `$self->{subject}` with no encoding or validation (unlike `priority`, which is normalized against an allowlist by `_normalize_priority`). `TicketPageRenderer::render_confirmation` retrieves it via the `subject` accessor and interpolates it directly into the HTML response with `say "<p>Subject: $subject</p>";`. The full chain: `$cgi->param('subject')` (source) -> `TicketSummary->new` -> `TicketSummary::subject` accessor -> `TicketPageRenderer::render_confirmation` (sink). Nothing in this path HTML-encodes the value before it reaches the response body, so a subject line such as `<script>alert(1)</script>` is emitted verbatim into the page and executes in the requester's browser.

## Fix

### File: TicketPageRenderer.pm

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

## Explanation

The fix applies `HTML::Entities::encode_entities()` to `$summary->subject` at the point it is read for rendering, immediately before interpolation into the HTML body, converting `<`, `>`, `&`, `"`, and `'` (and other non-ASCII/control characters covered by the module's default set) into their HTML entity equivalents. This is the output-encoding sink fix called for by the CWE-79 Perl guidance, applied only to the one field that is genuine free text; `ticket_id` is a server-generated integer and `priority` is already constrained to a fixed allowlist (`low`/`normal`/`high`/`urgent`, defaulting to `normal`) by `TicketSummary::_normalize_priority`, so neither needs additional encoding and neither was touched. Encoding a value that contains HTML metacharacters turns it into inert text rather than markup, closing the injection while leaving ordinary subject lines (including ones containing `<`, `&`, or quotes as legitimate text) displayed correctly, just escaped.

## Behaviour changes

- Subject text containing `<`, `>`, `&`, `"`, or `'` now renders as the visible literal character (via its HTML entity) instead of being interpreted as markup by the browser. This is the intended effect of the fix, not a side effect: previously such characters could alter page structure or execute script; now they display as plain text. No other output, argument, return value, or control flow changed - `ticket_id` and `priority` are emitted exactly as before, and the function's return value (`undef` via bare `return;`) is unchanged.
- library_recommendation: `HTML::Entities` (function `encode_entities`), part of the `HTML-Parser` CPAN distribution already named in the loaded `cwe/79/perl/INDEX.md` guidance. The guidance gives no minimum safe version for this module, so none is supplied here; confirm the resolved version against SCA/dependency tooling before merging, and add `HTML-Parser` to the project's manifest (e.g. `cpanfile`/`Makefile.PL`) if it is not already a declared dependency.

## Verification

Ran `perl -c` against the fixed file in a scratch copy outside the case directory: `TicketPageRenderer.pm syntax OK`. Also exercised it functionally in the same scratch location with a stub summary object whose `subject` was `<script>alert('xss')</script>`; the rendered output showed `<p>Subject: &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;</p>`, confirming the payload is neutralized while `ticket_id` and `priority` still render unencoded as before. `encode_entities` is imported from `HTML::Entities`, which is present in the local Perl installation (`perl -MHTML::Entities -e 'print "ok\n"'` succeeded) and is the exact function named in the loaded language guidance's Taint Sinks/Remediation Steps section, so no unverified names were introduced.

assumptions: none - the language (Perl), CWE (79), and data-flow chain were all given directly in the finding, and the guidance's named fix function (`encode_entities`) applied without needing a substitute.
