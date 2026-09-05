## Verdict

The code at line 27 outputs untrusted user input directly into HTML without escaping. Parameters from `$cgi->param('subject')` (line 12) and `$cgi->param('reply')` (line 13) are embedded in the HTML string at lines 21-22 and printed without entity encoding, allowing an attacker to inject arbitrary HTML and JavaScript.

## Source

Lines 12-13 receive untrusted input:
```
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');
```

These values flow directly into the HTML string constructed at lines 20-24 and are output at line 27.

## Fix

Use `CGI::escapeHTML()` to encode the user-supplied values before embedding them in HTML:

```perl
use CGI qw(escapeHTML);

my $ticket_subject = escapeHTML($cgi->param('subject'));
my $customer_reply = escapeHTML($cgi->param('reply'));

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $ticket_subject . "</h2>"
    . "<div class='reply'>" . $customer_reply . "</div>"
    . $status_badge
    . "</div>";

print $ticket_html;
```

Alternatively, use Perl's `HTML::Escape` module or similar HTML-encoding utilities to escape all HTML metacharacters (`<`, `>`, `"`, `&`, `'`) before output.

## Explanation

The vulnerability exists because user-controlled input is concatenated into an HTML string and printed to the response without any encoding. If `$ticket_subject` or `$customer_reply` contains `<script>alert('XSS')</script>`, the browser will execute it as code.

HTML entity encoding converts dangerous characters to safe representations (`<` becomes `&lt;`, `>` becomes `&gt;`, etc.), so the injected content is rendered as text rather than interpreted as markup or code. The `CGI::escapeHTML()` function is part of the standard CGI module already imported in this code and performs exactly this transformation.
