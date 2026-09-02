## Verdict
Confirmed XSS vulnerability. Untrusted user input from CGI parameter `subject` flows through `TicketSummary` to `TicketPageRenderer` and is rendered directly into HTML output without escaping, allowing arbitrary HTML/JavaScript injection.

## Source
`TicketPageRenderer.pm` line 19:
```perl
say "<p>Subject: $subject</p>";
```

Data origin: `ticket_controller.pl` line 14 — untrusted CGI parameter `subject` is passed to `TicketSummary->new()` without validation, stored in `$summary->{subject}`, and retrieved via accessor method.

## Fix
Escape HTML special characters before output. Replace line 19 in TicketPageRenderer.pm:

```perl
use HTML::Entities;

# In render_confirmation subroutine:
my $escaped_subject = HTML::Entities::encode_entities($subject);
say "<p>Subject: $escaped_subject</p>";
```

Alternatively, using CGI.pm's built-in escape (simpler if CGI is already in scope):
```perl
use CGI qw(escapeHTML);

# In render_confirmation subroutine:
say "<p>Subject: " . escapeHTML($subject) . "</p>";
```

## Explanation
The vulnerability exists because user-controlled input (`subject` parameter) reaches the HTML sink without neutralization. Perl's string interpolation does not perform HTML escaping — the text is inserted verbatim.

An attacker submitting `subject=<script>alert('XSS')</script>` would cause that script tag to be rendered in the HTML response, executing in the victim's browser.

The fix applies HTML entity encoding, converting unsafe characters (`<`, `>`, `&`, `"`, `'`) to their safe entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), so they render as literal text rather than executable markup.
