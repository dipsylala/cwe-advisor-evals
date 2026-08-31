## Verdict

Exploitable. Untrusted user input from CGI parameters is directly interpolated into HTML output without encoding, allowing injection of malicious scripts.

## Source

User-controlled input read from CGI parameters at lines 10-11:
- `$guest_name` from `$cgi->param('guest_name')`
- `$event_title` from `$cgi->param('event_title')`

## Fix

**Vulnerable code (line 18):**
```perl
print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

**Fixed code:**
```perl
print "<h2>Thanks, ", $cgi->escapeHTML($guest_name), "! You're confirmed for ", $cgi->escapeHTML($event_title), ".</h2>\n";
```

Alternatively, using concatenation:
```perl
print "<h2>Thanks, " . $cgi->escapeHTML($guest_name) . "! You're confirmed for " . $cgi->escapeHTML($event_title) . ".</h2>\n";
```

## Explanation

The fix wraps each user-controlled variable with `$cgi->escapeHTML()`, which converts special HTML characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This ensures user input is treated as text data rather than executable code, preventing attackers from injecting script tags (`<script>alert(1)</script>`) or event handlers (`"><img src=x onerror=alert(1)>`). The CGI module is already imported in the code, so no additional dependencies are required.

## Behaviour changes

None. HTML entities are decoded transparently by the browser during rendering, so legitimate content containing special characters will display correctly. For example, a name like `"Tom & Jerry"` will render as `"Tom &amp; Jerry"` in the HTML source but display as `"Tom & Jerry"` in the browser.
