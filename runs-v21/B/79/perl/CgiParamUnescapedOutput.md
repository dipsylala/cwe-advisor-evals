## Verdict

The reported finding is a confirmed, exploitable CWE-79 XSS vulnerability. User-supplied input from the `note` query parameter is output directly into an HTML `<p>` tag without encoding, allowing an attacker to inject malicious JavaScript that executes in the victim's browser.

## Source

Untrusted data enters the application via:
- `$cgi->param('note')` on line 18 — the reported finding
- `$cgi->param('ticket_id')` on line 10, output on line 14 — same vulnerability pattern

Both are obtained from CGI query parameters with no validation or encoding before output.

## Fix

### File: CgiParamUnescapedOutput.pl

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
print "<h2>Ticket #" . encode_entities($ticket_id) . "</h2>\n";
print "<p>Status: Open</p>\n";

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

## Explanation

The fix adds context-appropriate HTML encoding using `HTML::Entities::encode_entities()`, which is the recommended safe pattern for Perl applications handling CWE-79. CGI.pm's built-in `escapeHTML()` has version-dependent behavior (prior to 4.11, it does not properly escape single quotes in UTF-8 contexts), making it unsafe for general use; `encode_entities()` provides consistent, reliable HTML escaping across all charsets.

The fix changes both instances of raw parameter output (line 14: `ticket_id`, and line 18: `note`) by wrapping each with `encode_entities()`. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entities, preventing the browser from interpreting user input as HTML or JavaScript code. The string is still readable in the rendered page (entities render as their literal characters in HTML display) but is now treated as data, not executable code.

## Behaviour changes

- User-supplied text containing HTML special characters will now display safely. For example, input `<script>alert(1)</script>` will render as `&lt;script&gt;alert(1)&lt;/script&gt;` in the HTML response, preventing script execution.
- Legitimate content with ampersands, quotes, or angle brackets (e.g., names like "O'Brien", mathematical expressions, or code examples) will now render correctly without browser interpretation.
- The HTTP response body will be identical in size or slightly larger due to entity encoding (e.g., `<` becomes `&lt;`).
- No functional impact on the application's logic or user workflows—only the safety of output rendering is changed.
