## Verdict
Confirmed. `$cgi->param('note')` (and `$cgi->param('ticket_id')`) are attacker-controlled CGI parameters concatenated directly into the HTML response without encoding, allowing reflected XSS via the `note` or `ticket_id` query/form parameters.

## Source
`$cgi->param('note')` at line 18 (and `$cgi->param('ticket_id')` at line 10, used at line 14) — both read directly from the CGI request with no validation or encoding before being written into the HTML body.

## Fix

### File: CgiParamUnescapedOutput.pl
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
`CGI.pm`'s `escapeHTML()` method HTML-entity-encodes the special characters (`<`, `>`, `&`, `"`, `'`) that let attacker-supplied text break out of the surrounding markup and inject script or attributes. Both untrusted values reaching the output — `ticket_id` and `note` — are wrapped with `$cgi->escapeHTML(...)` at the point they are concatenated into the response, so any markup or script the user supplies is rendered as inert text rather than parsed as HTML. `escapeHTML` returns `undef` unchanged when passed `undef`, so a missing parameter still prints cleanly. No behavioral change occurs for legitimate values that do not contain HTML metacharacters.
