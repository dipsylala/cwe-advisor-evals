## Verdict

Confirmed. Cross-site scripting vulnerability at line 18 via unencoded output of `$cgi->param('note')` into HTML body text.

## Source

User-controlled input: `$cgi->param('note')` retrieves untrusted data from query parameter and passes it directly to the `print` statement without encoding.

Data flow: HTTP request query parameter → `$cgi->param('note')` → HTML body (line 18).

## Fix

Add `use HTML::Entities;` at the top of the script and apply `encode_entities()` to the parameter before output:

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

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

The key change: Line 18 now wraps `$cgi->param('note')` with `encode_entities()`, which converts special characters (`<`, `>`, `&`, `"`, `'`) to HTML entities.

## Explanation

The original code outputs untrusted user input directly into HTML context without encoding. An attacker can supply `note=<script>alert('XSS')</script>` as a query parameter, and the script executes in the victim's browser. By applying `HTML::Entities::encode_entities()`, all HTML metacharacters are converted to entity references (e.g., `<` becomes `&lt;`, `>` becomes `&gt;`), rendering any script payload as harmless text. This is the correct context-aware encoding for HTML body and attribute text, as specified in the CWE-79 Perl guidance. The vulnerability is eliminated because the browser treats the output as character data, not executable code.

## Behaviour changes

- User input containing HTML special characters (e.g., `<`, `>`, `&`, `"`, `'`) is now displayed as HTML entities instead of raw characters. A customer note containing "Tom & Jerry's <review>" now renders as "Tom &amp; Jerry&#039;s &lt;review&gt;" in the browser view, which is the intended and safe behaviour.
- Legitimate customer notes with angle brackets or ampersands are preserved and displayed correctly, just encoded for safe output. No data loss occurs.
- Script injection payloads are neutralized and rendered as text, preventing execution.
- HTTP response content remains well-formed HTML; the added encoding does not affect the HTML structure or layout.
