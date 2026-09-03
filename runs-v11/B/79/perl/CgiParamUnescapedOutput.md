## Verdict

Confirmed. Line 18 outputs untrusted user input directly into HTML without encoding, allowing XSS injection.

## Source

`$cgi->param('note')` on line 18 reads untrusted user input from the HTTP request parameter 'note'.

## Fix

Add `use HTML::Entities;` after the existing imports, then replace line 18:

**Before (vulnerable):**
```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

**After (fixed):**
```perl
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

The complete fixed file:
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

# HTML-encoded output prevents XSS injection
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

## Explanation

The `encode_entities()` function from HTML::Entities escapes special HTML characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This converts any injected script tags or event handlers into safe, harmless text that renders as literal characters in the browser rather than executing as code. The fix isolates the XSS attack surface by applying HTML encoding at the output sink where user data enters the HTML document body.

## Behaviour changes

- Legitimate note content containing `<`, `>`, `&`, or quotes now renders as escaped entities (e.g., `<` displays as `&lt;`) rather than raw characters. This is the correct and expected behaviour for user-supplied content in HTML contexts.
- An attacker-supplied payload like `<script>alert(1)</script>` now safely renders as escaped text in the page rather than executing as a script.
- No functional impact on the application's intended workflow - ticket notes display correctly and safely.
