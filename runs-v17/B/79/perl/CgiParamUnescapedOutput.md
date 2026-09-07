## Verdict

exploitable

## Source

`$cgi->param('note')` on line 18: user-supplied input from CGI query parameter, untrusted and attacker-controlled.

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

The vulnerability allows XSS attacks because untrusted user input from `$cgi->param('note')` is rendered directly into HTML output without encoding. An attacker can inject `<script>alert(1)</script>` or event handlers like `onmouseover='alert(1)'` which will execute in the victim's browser. The fix applies `encode_entities()` from the standard HTML::Entities module to neutralize HTML metacharacters (`<`, `>`, `&`, `"`, `'`) before output. This transforms user input into HTML entities, rendering it as displayable text rather than executable code. The same encoding is applied to `$ticket_id` on line 14 to close the same weakness there. HTML::Entities is a core CPAN module (available as a dependency in any modern Perl environment).

## Behaviour changes

- Added `use HTML::Entities;` import statement to make `encode_entities()` available
- Line 14: wrapped `$ticket_id` with `encode_entities()` to apply context-specific encoding
- Line 18: wrapped `$cgi->param('note')` with `encode_entities()` to apply context-specific encoding

These changes apply output encoding only at the HTML context sinks where the data is rendered; the underlying data flow is unchanged and `print` still returns 1 on success. The encoding transformation is irreversible (encoded entities cannot be decoded back to the original in HTML context), which is correct for XSS defence—the attacker's payload becomes harmless text.
