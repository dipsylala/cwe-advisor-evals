## Verdict

- **cwe_id**: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'))
- **location**: ManualHtmlConstructionPerl.pl, line 27 (sink); built at lines 20-24
- **verdict**: exploitable
- **confidence**: high

## Source

- `$ticket_subject = $cgi->param('subject')` (line 12) - untrusted CGI request parameter
- `$customer_reply = $cgi->param('reply')` (line 13) - untrusted CGI request parameter

Both values flow unmodified into the `$ticket_html` string built at lines 20-24 (`"<h2>" . $ticket_subject . "</h2>"` and `"<div class='reply'>" . $customer_reply . "</div>"`), which is written to the response at the sink, `print $ticket_html;` (line 27). Neither value is validated, filtered, or encoded anywhere between source and sink.

`$ticket_id` (line 11) is also a CGI parameter but only reaches `build_status_badge()`, which tests it with `defined $id` and returns one of two fixed strings (`Open`/`Unknown`) - it never interpolates `$id` into output, so that path is not exploitable.

## Fix

Vulnerable code:

```perl
my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"
    . "<div class='reply'>" . $customer_reply . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;
```

Fixed code (add `use HTML::Entities;` alongside the existing `use` statements, then encode both untrusted fields at the point they are concatenated into the HTML string):

```perl
use HTML::Entities;

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;
```

- **library_recommendation**: `HTML::Entities` (core-adjacent, ships with the `libwww-perl`/`HTML-Parser` distribution commonly already present alongside `CGI.pm`). No minimum-safe-version claim is made here - the knowledge base entry supplies no version floor for `HTML::Entities`, and per policy no version is filled in from recall. Confirm the resolved version via SCA/dependency-check tooling before merging.

## Explanation

`$ticket_subject` and `$customer_reply` are attacker-controlled CGI parameters that were concatenated directly into an HTML fragment and printed to the response with no encoding, letting a value like `<script>...</script>` execute in the viewing browser. Wrapping both values in `HTML::Entities::encode_entities()` at the point they enter the HTML string converts `<`, `>`, `&`, and quote characters into their HTML entity equivalents, so the data is rendered as literal text inside the `<h2>` and `<div class='reply'>` elements rather than as markup. Both fields are HTML-body/element-content contexts (not attributes or script blocks), so a plain `encode_entities()` call with its default character set is the correct encoding for this sink; `$status_badge` and the surrounding static markup are left untouched since they contain no untrusted data.

## Behaviour changes

- Added `use HTML::Entities;` - required to call `encode_entities()`; no functional effect beyond making the encoder available.
- `$ticket_subject` and `$customer_reply` are now HTML-entity-encoded before being embedded in the response. For input containing `<`, `>`, `&`, or quote characters, the rendered page now shows the literal characters (e.g. `&lt;`) instead of treating them as markup - this is the intended effect of the fix, not an incidental behaviour change. Legitimate subjects/replies without those characters render identically to before.
- No other differences: `print`'s return value, the response headers set at line 15, `$status_badge`'s construction, and the overall HTML structure are all unchanged.
