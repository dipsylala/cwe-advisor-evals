## Verdict

Exploitable. Confidence: high.

## Source

`$cgi->param('note')` (line 10 lookup pattern applies directly at the sink; the parameter is read inline at line 18) - the `note` CGI query parameter, fully attacker-controlled, read via `CGI->new`'s `param()`.

## Fix

### File: CgiParamUnescapedOutput.pl

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities qw(encode_entities);

# Helpdesk ticket lookup page: renders the ticket ID and an optional
# customer-supplied note back onto the confirmation screen.

my $cgi = CGI->new;
my $ticket_id = $cgi->param('ticket_id');

print $cgi->header;
print "<html><head><title>Ticket Lookup</title></head><body>\n";
print "<h2>Ticket #" . $ticket_id . "</h2>\n";
print "<p>Status: Open</p>\n";

print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";

print "</body></html>\n";
```

## Explanation

The `note` query parameter is read straight from the request and concatenated into the HTML response body with no encoding, so a value like `<script>...</script>` executes in the victim's browser (reflected XSS). The fix HTML-encodes the parameter at the point it enters the HTML body context using `HTML::Entities::encode_entities()`, called with its default character set via the `qw(encode_entities)` import from `HTML::Entities` - the Perl guidance's named safe pattern for this sink. This turns `<`, `>`, `&`, and quote characters into their entity forms so the value is rendered as inert text rather than parsed as markup, while leaving legitimate note content (including literal `<`, `&`, or quotes) fully readable on the page. `$ticket_id` at line 14 has the same unencoded-output shape but is outside the reported finding (line 18) and was left unchanged.

## Behaviour changes

- Added `use HTML::Entities qw(encode_entities);` - new import required to call the encoding function; no runtime behavior beyond loading the module.
- `note` output is now HTML-entity-encoded before concatenation - this is the fix itself, not incidental. Legitimate note text containing `<`, `>`, `&`, or quotes now renders as escaped entities (visually identical in a browser to the literal characters) rather than being parsed as HTML; this is the intended, correct change for eliminating the injection.
- No other arguments, return values, or output paths were altered. `$ticket_id`, `$cgi->header`, and all other `print` statements are unchanged.

## Verification

Syntax-checked with `perl -c` (Perl 5.38.2). The `CGI` module is not installed in this environment, so `use CGI;` / `CGI->new` were stubbed out for the check only (not part of the fix) to isolate syntax validity of the changed lines; with that stub, `perl -c` reported "syntax OK". `HTML::Entities` was separately confirmed loadable in this environment (`perl -MHTML::Entities -e 'print "ok\n"'` succeeded), and `encode_entities` is the exact function named in the loaded Perl guidance (`cwe/79/perl/INDEX.md`).

## Assumptions

- The finding targets only line 18 (`note`); the structurally identical unescaped output of `$ticket_id` at line 14 was intentionally left unmodified as out of scope for this specific finding.
- `CGI.pm` itself could not be installed/loaded in this sandbox to run a full end-to-end `perl -c` against the unmodified module chain; verification was done by isolating the changed lines with a stub, per above.
