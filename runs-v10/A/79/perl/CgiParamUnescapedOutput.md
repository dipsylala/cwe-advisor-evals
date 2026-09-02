## Verdict

Confirmed CWE-79 (Reflected Cross-Site Scripting). Line 18 outputs unsanitized user input directly into HTML context without escaping special characters, allowing an attacker to inject arbitrary HTML and JavaScript.

## Source

The source is `$cgi->param('note')` on line 18, which retrieves user-supplied input from the query string or form data. The sink is the direct concatenation into the HTML output via `print`.

## Fix

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use CGI::Util qw(html_escape);

# Helpdesk ticket lookup page: renders the ticket ID and an optional
# customer-supplied note back onto the confirmation screen.

my $cgi = CGI->new;
my $ticket_id = html_escape($cgi->param('ticket_id'));

print $cgi->header;
print "<html><head><title>Ticket Lookup</title></head><body>\n";
print "<h2>Ticket #" . $ticket_id . "</h2>\n";
print "<p>Status: Open</p>\n";

# FIXED: Escape HTML special characters in user input before output
print "<p>Customer note: " . html_escape($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

## Explanation

The fix applies HTML entity encoding to all user-controlled data before inserting it into the HTML output. The `html_escape()` function from `CGI::Util` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting them as markup or script tags. This ensures that if an attacker submits `<script>alert('xss')</script>` in the `note` parameter, it renders as literal text in the page rather than executing. The fix is applied to both the `note` parameter (line 18) and the `ticket_id` parameter (line 10) to comprehensively address all reflected outputs.
