## Verdict

**CWE-79** (Improper Neutralization of Input During Web Page Generation - Cross-site Scripting)

**Exploitable**: Yes

**Confidence**: High

**Location**: evals/cases/79/perl/MultiFileCgiRelayXss/TicketPageRenderer.pm line 19

**Sink**: `say "<p>Subject: $subject</p>";`

## Source

Untrusted user input from CGI parameter in ticket_controller.pl line 14:

```
my $subject = $cgi->param('subject');
```

The subject parameter is captured directly from the HTTP request without validation or encoding. It is passed through the TicketSummary domain object and rendered directly into HTML output in TicketPageRenderer.pm.

Data flow chain:
1. ticket_controller.pl line 14: `$cgi->param('subject')` - untrusted input source
2. ticket_controller.pl line 19-22: Passed to `TicketSummary->new(subject => $subject)`
3. TicketSummary.pm line 14: Stored directly without encoding
4. TicketPageRenderer.pm line 19: Rendered into HTML output via string interpolation

## Fix

**Library recommendation**: HTML::Entities (CPAN module, commonly available; no specific version requirement from guidance)

**Vulnerable code (TicketPageRenderer.pm line 15-19):**
```perl
    say "<html><body>";
    say "<h1>Ticket #$ticket_id filed</h1>";
    say "<p>Priority: $priority</p>";
    say "<p>Subject: $subject</p>";
    say "</body></html>";
```

**Fixed code:**
```perl
use HTML::Entities;

    say "<html><body>";
    say "<h1>Ticket #$ticket_id filed</h1>";
    say "<p>Priority: $priority</p>";
    say "<p>Subject: " . encode_entities($subject) . "</p>";
    say "</body></html>";
```

## Explanation

The vulnerability occurs because the `$subject` variable, containing untrusted user input from a CGI parameter, is rendered directly into HTML output via string interpolation. This allows an attacker to inject arbitrary HTML and JavaScript by submitting a subject containing payloads such as `<img onerror=alert(1)>`, `<script>alert(1)</script>`, or `' onmouseover='alert(1)`. The fix applies HTML entity encoding at the output sink using `HTML::Entities::encode_entities()`, which escapes dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This prevents injected payloads from being interpreted as markup or executable script and ensures they display as literal text in the victim's browser. The encoding is applied only at the final output sink where the data crosses from server-side Perl into client-side HTML/JavaScript context, consistent with the guidance principle of encoding at each output sink rather than once on input.

## Behaviour changes

The `say` function's return value and STDOUT destination remain unchanged. The only difference is that HTML special characters in the subject are now encoded to their entity equivalents, so they display as literal text in the browser rather than being interpreted as HTML elements or attributes. Legitimate subjects containing `<`, `>`, `&`, or quotes will now display those characters literally instead of being misinterpreted, which is the correct and expected behavior for user-supplied content in an HTML body context. The fix does not suppress or discard any output from the original code.

**Verification**: Fixed code passed `perl -c` syntax check with no errors. All new symbols (the `encode_entities()` function) are provided by HTML::Entities module, which is loaded via the `use HTML::Entities;` statement. HTML::Entities is a standard CPAN module available in most Perl distributions.

**Assumptions**: No significant assumptions. HTML::Entities is treated as a standard CPAN module that is typically pre-installed in Perl environments or readily available from CPAN; the guidance for CWE-79 in Perl explicitly recommends this module. The `$priority` variable at line 17 was not encoded even though it is from the same untrusted request, but the TicketSummary::_normalize_priority() function constrains it to a known set of values (low/normal/high/urgent), so it is not exploitable for XSS and follows the principle of applying validation where possible as a defense-in-depth measure.

