## Verdict
exploitable

## Source
Lines 12-13: User input from CGI parameters
- `$ticket_subject = $cgi->param('subject')`
- `$customer_reply = $cgi->param('reply')`

These values originate from untrusted query parameters and are directly interpolated into an HTML string without any encoding.

## Fix

**Vulnerable code (lines 20-24):**
```perl
my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"
    . "<div class='reply'>" . $customer_reply . "</div>"
    . $status_badge
    . "</div>";
```

**Fixed code:**
```perl
use HTML::Entities;

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";
```

## Explanation
The vulnerability occurs because user-supplied input from `$cgi->param('subject')` and `$cgi->param('reply')` is concatenated directly into an HTML string without encoding. When this unencoded HTML is output via `print $ticket_html` (line 27), an attacker can inject malicious scripts such as `<script>alert(1)</script>` or event handlers like `<div onmouseover="alert(1)">` that execute in the victim's browser. The fix applies `encode_entities()` from `HTML::Entities` to both user-controlled values, which converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), ensuring the data remains text content rather than executable code.

## Behaviour changes
- **Added import:** `use HTML::Entities;` is required for the `encode_entities()` function. This introduces a compile-time dependency on the HTML::Entities module (part of the HTML-Parser distribution, commonly available in standard Perl environments).
- **Encoding behavior:** All HTML metacharacters in `$ticket_subject` and `$customer_reply` are now converted to HTML entities. Legitimate content containing `<`, `&`, or quotes will be displayed correctly as text (e.g., `"foo & bar"` displays as text, not as an ampersand entity expansion). This preserves correct output while preventing script injection.
- **No signature changes:** The `build_status_badge()` subroutine remains unchanged as it returns hardcoded HTML with no untrusted data.
