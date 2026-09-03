## Verdict

exploitable

## Source

HTTP request parameters `guest_name` and `event_title` supplied via CGI.pm's `param()` method (lines 10-11), originating from untrusted user input (query parameters or form data).

## Fix

**Vulnerable code (line 18):**
```perl
print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

**Fixed code:**
Add `use HTML::Entities;` to the import section (after line 4), then encode the variables at the output sink:
```perl
print "<h2>Thanks, " . encode_entities($guest_name) . "! You're confirmed for " . encode_entities($event_title) . ".</h2>\n";
```

## Explanation

The vulnerability occurs because untrusted user input from HTTP request parameters is directly interpolated into HTML output without encoding. An attacker can inject malicious HTML/JavaScript via the `guest_name` or `event_title` parameters (for example, `<script>alert(1)</script>` or `"><script>alert(1)</script>`). 

The fix applies context-aware HTML encoding using `HTML::Entities::encode_entities()` at the point of output, which escapes special characters (`<`, `>`, `&`, `"`, `'`) so they are rendered as harmless text rather than interpreted as HTML/JavaScript code. This ensures the user input remains data and cannot break out of the HTML context to execute arbitrary scripts in the victim's browser.

## Behaviour changes

none
