## Verdict

Exploitable. Untrusted user input (`$ticket_subject` and `$customer_reply`) is concatenated directly into HTML output without encoding, allowing arbitrary script injection in the rendered page.

## Source

User-supplied parameters from CGI query string:
- `$ticket_subject` from `$cgi->param('subject')` (line 12)
- `$customer_reply` from `$cgi->param('reply')` (line 13)

Both sources flow unvalidated into HTML string construction (lines 20-24) and are output to the browser on line 27.

## Fix

Vulnerable code (lines 20-24):
```perl
my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"
    . "<div class='reply'>" . $customer_reply . "</div>"
    . $status_badge
    . "</div>";
```

Fixed code:
```perl
use HTML::Entities;

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";
```

## Explanation

The fix adds `use HTML::Entities;` to the imports and wraps both untrusted user inputs with `encode_entities()` before interpolating them into the HTML string. This converts special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring they are rendered as text content rather than interpreted as HTML tags or attributes. An attacker-supplied payload like `<script>alert(1)</script>` becomes `&lt;script&gt;alert(1)&lt;/script&gt;`, which displays as literal text in the browser. This context-aware output encoding at the sink is the primary defence against XSS in HTML body content.

## Behaviour changes

None. The `encode_entities()` function returns a scalar string with the same logical value (the user's input text), just with HTML metacharacters escaped. The `print` statement continues to output the HTML string to stdout with identical return value (1 on success). The visible output in the browser is identical for legitimate input containing no special characters, and correctly sanitized for input containing characters that previously risked XSS injection.
