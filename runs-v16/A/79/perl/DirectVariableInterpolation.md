## Verdict

**Confirmed XSS vulnerability.** Line 18 interpolates unsanitized user input directly into HTML output.

## Source

CGI parameters `guest_name` and `event_title` are obtained via `$cgi->param()` at lines 10-11 without escaping, then interpolated directly into the HTML response at line 18. An attacker can inject arbitrary HTML/JavaScript through these parameters.

## Fix

Escape HTML special characters before interpolating user input:

```perl
print "<h2>Thanks, " . CGI::escapeHTML($guest_name) . "! You're confirmed for " . CGI::escapeHTML($event_title) . ".</h2>\n";
```

Alternatively, use concatenation with the CGI module's escaping:

```perl
use CGI qw(escapeHTML);
print "<h2>Thanks, " . escapeHTML($guest_name) . "! You're confirmed for " . escapeHTML($event_title) . ".</h2>\n";
```

## Explanation

The CGI module's `escapeHTML()` function converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents, neutralizing script injection payloads. Direct string interpolation in Perl (using `$variable` inside double-quoted strings) does not escape HTML, so the fix requires explicit escaping before output. This approach preserves the response structure while preventing the attacker from breaking out of the text context.
