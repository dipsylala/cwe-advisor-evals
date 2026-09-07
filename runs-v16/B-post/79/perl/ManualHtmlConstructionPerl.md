## Verdict

Exploitable.

## Source

User input `$ticket_subject` and `$customer_reply` derived from untrusted CGI parameters on lines 12–13.

## Fix

**Vulnerable code:**

```perl
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"
    . "<div class='reply'>" . $customer_reply . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;
```

**Fixed code:**

```perl
use HTML::Entities;

my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;
```

## Explanation

The original code concatenates untrusted CGI parameters directly into HTML without any encoding. An attacker can inject a payload such as `<script>alert(1)</script>` in the `subject` or `reply` parameter, which will execute in the victim's browser. The fix applies `encode_entities()` from the `HTML::Entities` module to both `$ticket_subject` and `$customer_reply` before they are embedded in the HTML string. This function escapes special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring that user-supplied data is rendered as text content rather than executable code.

## Behaviour changes

None. The `encode_entities()` function returns a string with special characters escaped, which when printed produces the same visible output for legitimate content (the angle brackets and quotes appear as entities in the HTML source, but render as literal characters in the browser). The function does not discard or alter any values, and does not change the output structure. Legitimate content containing `<`, `>`, `&`, or quotes will render correctly as text.
