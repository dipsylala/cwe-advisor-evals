## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation, Cross-Site Scripting)
- **Location**: `ManualHtmlConstructionPerl.pl`, line 27 (`print $ticket_html;`)

## Source

- `$ticket_subject = $cgi->param('subject')` (line 12) - untrusted request parameter
- `$customer_reply = $cgi->param('reply')` (line 13) - untrusted request parameter

Both values flow unmodified into `$ticket_html` (lines 20-24), concatenated directly into `<h2>` and `<div class='reply'>` body content with no encoding step in between, then reach the sink at line 27 (`print $ticket_html`), which writes the string to the HTTP response body as `text/html`.

`$ticket_id` (line 11) also originates from `$cgi->param('ticket_id')` but is only passed to `build_status_badge()`, which uses it solely in `defined $id` (line 33) and never interpolates it into output - it does not reach an HTML sink and is not part of this finding.

## Fix

Vulnerable code (lines 20-24):

```perl
my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"                       # unescaped, in HTML body
    . "<div class='reply'>" . $customer_reply . "</div>"       # unescaped, in HTML body
    . $status_badge
    . "</div>";
```

Fixed code:

```perl
use HTML::Entities qw(encode_entities);
...
my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";
```

`use HTML::Entities qw(encode_entities);` is added to the `use` block near the top of the file alongside the existing `use CGI;`. `HTML::Entities` ships in Perl core and needs no version pin.

## Explanation

`$ticket_subject` and `$customer_reply` are attacker-controlled CGI parameters that were concatenated straight into HTML body content (inside `<h2>` and a `<div>`) with no output encoding, so a value like `<script>...</script>` or an `<img onerror=...>` tag submitted as `subject` or `reply` would execute in the viewing browser. Wrapping each value in `HTML::Entities::encode_entities()` at the point it is written into the HTML string converts `<`, `>`, `&`, and quote characters to their entity equivalents, so the data can no longer break out of the surrounding HTML body text and is rendered as literal content instead of markup. Both values land only in HTML body text (not inside an unquoted attribute or a script/URL context), so `encode_entities()` with its default character set is the correct encoding for this sink; `$status_badge` is server-generated from a fixed set of literal strings and required no change.

## Behaviour changes

None. The fix only wraps the two tainted values in `encode_entities()` at the same point they were already being concatenated; it does not change what is returned, what arguments are passed elsewhere, or the print/response flow. The only user-visible effect is that HTML metacharacters in the ticket subject or reply (`<`, `>`, `&`, quotes) now render as their literal characters (e.g. `&lt;`) instead of being interpreted as markup - which is the intended correction, not a side effect.
