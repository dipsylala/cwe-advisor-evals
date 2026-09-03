## Verdict

Exploitable. Untrusted user input from the CGI `subject` parameter flows without validation or encoding through `TicketSummary` to the HTML output sink in `TicketPageRenderer`.

## Source

`$subject` originates from `$cgi->param('subject')` in `ticket_controller.pl` (line 14), which reads untrusted data directly from the HTTP request. The value passes through `TicketSummary->new(subject => $subject)` where it is stored in the object without validation or escaping.

## Fix

**Vulnerable code** in `TicketPageRenderer.pm` (line 19):

```perl
say "<p>Subject: $subject</p>";
```

**Fixed code:**

```perl
use HTML::Entities;

# ... in render_confirmation subroutine:
say "<p>Subject: " . encode_entities($subject) . "</p>";
```

The `encode_entities()` function from `HTML::Entities` escapes HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), neutralizing any attempt to break out of the HTML text context and inject script tags or event handlers.

## Explanation

XSS occurs when untrusted data is interpolated directly into HTML without encoding, allowing attackers to inject arbitrary HTML and JavaScript. An attacker submitting a `subject` like `<script>alert(1)</script>` or `" onmouseover="alert(1)` would have that code execute in the victim's browser. The fix applies HTML entity encoding at the output sink to ensure that user-supplied text is rendered as literal text, not HTML markup or attributes. This is the Perl-specific safe pattern recommended in `cwe/79/perl`: using `HTML::Entities::encode_entities()` for HTML body and attribute contexts. Since `HTML::Entities` is widely used and available on CPAN, no version floor needs to be specified for standard remediation; confirm against your environment's SCA tooling.

## Behaviour changes

None. The `encode_entities()` function preserves the exact text value; legitimate content containing `<`, `>`, `&`, or quotes still displays correctly as rendered entities. The contract of the `say` statement is unchanged: it still outputs a complete HTML paragraph line to stdout. The change only affects how the `$subject` value is formatted before insertion, replacing unsafe interpolation with safe encoding.
