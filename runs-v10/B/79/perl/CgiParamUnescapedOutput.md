## Verdict

The finding is valid. Line 18 outputs unsanitized user input directly into the HTML response body, allowing XSS injection.

## Source

`$cgi->param('note')` — HTTP query parameter 'note' from the CGI request, attacker-controlled.

## Fix

Add `use HTML::Entities;` import at the top of the file (after `use CGI;`), then encode the parameter value at the output sink on line 18.

**Vulnerable code:**
```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

**Fixed code:**
```perl
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

**Full file with fix applied:**

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities;

# Helpdesk ticket lookup page: renders the ticket ID and an optional
# customer-supplied note back onto the confirmation screen.

my $cgi = CGI->new;
my $ticket_id = $cgi->param('ticket_id');

print $cgi->header;
print "<html><head><title>Ticket Lookup</title></head><body>\n";
print "<h2>Ticket #" . $ticket_id . "</h2>\n";
print "<p>Status: Open</p>\n";

# FIXED: HTML-encode customer note to prevent XSS injection
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

## Explanation

The vulnerability occurs because the user-supplied 'note' parameter is output directly into HTML without any encoding. An attacker can inject arbitrary JavaScript by supplying a crafted note value such as `<script>alert('XSS')</script>` or `<img src=x onerror=alert(1)>`. The browser will interpret the injected tags as code rather than data, executing the attacker's script in the victim's context.

The fix applies `encode_entities()` from the HTML::Entities module at the output sink. This function converts dangerous HTML metacharacters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring the browser treats the content as text data, not executable code. The encoding is context-specific to HTML body text and is applied at the point of output, not on input, because the same value might be rendered into different contexts (body, attribute, JavaScript, URL) with different encoding requirements.

## Behaviour changes

With the fix applied:

- User input containing special characters (`<`, `>`, `&`, quotes) will be HTML-encoded before output, converting them to entity references
- Legitimate note content is preserved and displayed correctly; for example, a note like "Refund < $100" will display as written with the `<` visible to users, not interpreted as an HTML tag
- XSS payloads are neutralized: `<script>alert(1)</script>` becomes `&lt;script&gt;alert(1)&lt;/script&gt;` in the HTML output, preventing execution
- Page rendering and functionality remain unchanged; the fix only escapes output data without altering page structure or logic
- Performance impact is negligible (encoding a short string on each request)
