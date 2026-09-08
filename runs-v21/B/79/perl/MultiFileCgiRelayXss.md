## Verdict

Confirmed. The vulnerability is exploitable through the call chain: `ticket_controller.pl` line 14 reads untrusted CGI parameter `subject` → `TicketSummary` line 14 stores it raw → `TicketPageRenderer.pm` line 19 renders it directly into HTML without encoding.

## Source

**Entry point** (ticket_controller.pl, line 14):
```perl
my $subject = $cgi->param('subject');
```
Untrusted user input from CGI request parameter. No validation or constraint is applied.

**Data flow**:
- Line 20 of ticket_controller.pl passes raw subject to `TicketSummary->new()`
- TicketSummary.pm line 14 stores it in object: `subject => $args{subject}`
- TicketSummary.pm line 29 returns it raw from accessor: `sub subject { return $_[0]->{subject}; }`
- TicketPageRenderer.pm line 13 retrieves it: `my $subject = $summary->subject;`

**Sink** (TicketPageRenderer.pm, line 19):
```perl
say "<p>Subject: $subject</p>";
```
Unsafe interpolation of untrusted subject into HTML body context.

The sink produces HTML output to stdout via `say`. The attacker can inject arbitrary HTML/JavaScript by sending a subject parameter containing tags like `<script>alert(1)</script>` or event handlers like `" onmouseover="alert(1)`.

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
    say "<p>Subject: " . encode_entities($subject) . "</p>";
    say "</body></html>";

    return;
}

1;
```

## Explanation

The fix applies HTML entity encoding to the untrusted `$subject` variable at the output sink. `HTML::Entities::encode_entities()` converts special characters that have meaning in HTML (`<`, `>`, `&`, `"`, `'`) into their named entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), rendering them as data rather than executable code or attribute delimiters.

This prevents attackers from breaking out of the HTML context to inject scripts or event handlers. An attacker submitting `<script>alert(1)</script>` as the subject will have it rendered as literal text `&lt;script&gt;alert(1)&lt;/script&gt;` instead of being executed. Similarly, attribute-breakout attempts like `" onmouseover="alert(1)` become `&quot; onmouseover=&quot;alert(1)` and are treated as part of the text node.

The other fields (`$ticket_id` and `$priority`) do not require encoding: `$ticket_id` is an incrementing integer, and `$priority` is normalized through an allowlist in TicketSummary (lines 23-26) that maps it to one of four known values, so it is server-controlled and safe.

## Behaviour changes

**Output change**: Legitimate input containing HTML metacharacters (e.g., a subject line "Q&A: How to use <div> tags") will now be displayed with escaped entities in the raw HTML source, but will render correctly in the browser. No functional regression—users see the exact text they typed. The escaping is invisible in normal browser rendering.

**No breaking changes to APIs or call chain**: The fix is isolated to the sink; TicketSummary and ticket_controller.pl require no changes. The subject value is still passed as a plain string through the chain.

**Performance**: Negligible—HTML entity encoding is a single-pass linear scan of the string, no measurable overhead for typical ticket subject lengths.
