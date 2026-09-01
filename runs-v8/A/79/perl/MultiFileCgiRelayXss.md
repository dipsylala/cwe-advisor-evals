## Verdict
CONFIRMED. The vulnerability is a stored XSS through unescaped HTML interpolation of user-controlled input.

## Source
The vulnerability originates at line 14 of `ticket_controller.pl`:
```
my $subject = $cgi->param('subject');
```
This untrusted parameter is passed through `TicketSummary->new()` and stored without validation or sanitization.

## Fix
In `TicketPageRenderer.pm` line 19, replace the unescaped interpolation with HTML-escaped output:

```perl
use CGI qw(:standard);

# Change line 19 from:
say "<p>Subject: $subject</p>";

# To:
say "<p>Subject: " . escapeHTML($subject) . "</p>";
```

Alternatively, use `HTML::Entities::encode_entities()` from the HTML::Entities module:

```perl
use HTML::Entities;

say "<p>Subject: " . encode_entities($subject) . "</p>";
```

## Explanation
The vulnerability occurs because user-supplied input (`$subject`) is directly interpolated into HTML output without escaping special characters. An attacker can inject arbitrary HTML and JavaScript by submitting input like `"><script>alert('XSS')</script><p>`, which becomes executable code in the browser.

The fix escapes HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring they are rendered as literal text rather than interpreted as markup. Both `CGI::escapeHTML()` and `HTML::Entities::encode_entities()` are standard, maintained options. The CGI module is already imported in the entry point, making `escapeHTML()` the most straightforward choice without additional dependencies.
