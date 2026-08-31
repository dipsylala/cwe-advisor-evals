## Verdict
The vulnerability is confirmed. Unsanitized user input from CGI parameters is directly interpolated into HTML output without escaping, enabling arbitrary HTML and JavaScript injection.

## Source
Line 18 interpolates `$guest_name` and `$event_title` directly into the HTML output:
```perl
print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

Both variables receive user-supplied data from CGI parameters (lines 10-11) and are never HTML-escaped before being written to the response.

## Fix
Add HTML entity encoding using CGI::Util, which is already available through the CGI module:

```perl
use CGI::Util qw(escape_html);

# Line 18 becomes:
print "<h2>Thanks, " . escape_html($guest_name) . "! You're confirmed for " . escape_html($event_title) . ".</h2>\n";
```

Alternatively, use the CGI object's escapeHTML method:
```perl
print "<h2>Thanks, " . $cgi->escapeHTML($guest_name) . "! You're confirmed for " . $cgi->escapeHTML($event_title) . ".</h2>\n";
```

## Explanation
Direct variable interpolation in Perl double-quoted strings includes the raw value without encoding. If `guest_name` contains `<script>alert('xss')</script>`, it renders directly into the HTML and executes in the browser.

HTML entity encoding converts special characters (`<`, `>`, `&`, `"`, `'`) to their escaped forms (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting them as markup. The `escape_html()` function from CGI::Util (or `$cgi->escapeHTML()`) performs this encoding and is the standard approach for Perl web applications using CGI.
