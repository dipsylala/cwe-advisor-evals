## Verdict

The finding is confirmed. Line 18 contains a cross-site scripting vulnerability where user-controlled input from CGI parameters is directly interpolated into HTML output without escaping.

## Source

Variables `$guest_name` and `$event_title` are derived from untrusted CGI parameters via `$cgi->param()` (lines 10–11) and directly interpolated into the HTML string on line 18 without any escaping or encoding.

## Fix

Escape HTML special characters in both variables before interpolating them into the HTML output. Use CGI's `escapeHTML()` function:

```perl
my $escaped_name  = $cgi->escapeHTML($guest_name);
my $escaped_title = $cgi->escapeHTML($event_title);
print "<h2>Thanks, $escaped_name! You're confirmed for $escaped_title.</h2>\n";
```

Alternatively, escape inline within the interpolation using CGI's `escape()` method or the `HTML::Entities` module's `encode_entities()` function if additional control is needed.

## Explanation

Perl string interpolation substitutes variable values directly into the string without encoding HTML metacharacters. An attacker controlling the `guest_name` or `event_title` parameters can inject arbitrary HTML or JavaScript—for example, `"><script>alert('XSS')</script><h2>"` to break out of the tag and execute code in the victim's browser. Escaping converts metacharacters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting them as markup or script. This ensures user input is treated as content, not executable code.
