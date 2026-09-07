## Verdict

Confirmed. Line 18 outputs user-supplied input directly to HTML without escaping, allowing XSS injection via the `note` parameter. The same pattern appears on line 14 with the `ticket_id` parameter.

## Source

The vulnerability is in the CGI parameter output on line 18:

```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

The `note` parameter is read from the query string and printed directly into the HTML page without HTML entity escaping. An attacker can inject arbitrary HTML and JavaScript by providing a payload like `<script>alert('xss')</script>` in the `note` parameter.

## Fix

### File: CgiParamUnescapedOutput.pl

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use CGI::Util qw(html_escape);

# Helpdesk ticket lookup page: renders the ticket ID and an optional
# customer-supplied note back onto the confirmation screen.

my $cgi = CGI->new;
my $ticket_id = $cgi->param('ticket_id');

print $cgi->header;
print "<html><head><title>Ticket Lookup</title></head><body>\n";
print "<h2>Ticket #" . html_escape($ticket_id) . "</h2>\n";
print "<p>Status: Open</p>\n";

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print "<p>Customer note: " . html_escape($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

## Explanation

The fix uses `CGI::Util::html_escape()` to encode HTML special characters in user-supplied input before rendering it in the page. This function converts characters like `<`, `>`, `&`, and quotes into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, etc.), preventing the browser from interpreting them as markup or script.

The fix is applied to both the `ticket_id` (line 14) and `note` (line 18) parameters, since both are user-controlled and vulnerable to XSS. The import statement `use CGI::Util qw(html_escape)` makes the escaping function available for use.
