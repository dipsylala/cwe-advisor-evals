## Verdict

Exploitable. CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')).

- **Location**: `ManualHtmlConstructionPerl.pl`, line 27 (`print $ticket_html;`)
- **Confidence**: high

## Source

Two CGI request parameters are read via `CGI->param()` and flow, unmodified, into the sink:

- `$ticket_subject = $cgi->param('subject')` (line 12)
- `$customer_reply = $cgi->param('reply')` (line 13)

(`$ticket_id`, also read from `param('ticket_id')`, only feeds a `defined $id` check in `build_status_badge()` and is never emitted, so it is not part of this taint path.)

Both tainted values are concatenated directly into `$ticket_html` (lines 20-24) with no encoding, and the resulting string is written to the HTTP response body at line 27 (`print $ticket_html;`), which is the reported sink. `build_status_badge()`'s output is a static, attacker-uncontrolled string and is not part of the vulnerable flow.

## Fix

### File: ManualHtmlConstructionPerl.pl
```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities qw(encode_entities);

# Renders a single support ticket, including its subject line and the
# latest customer reply, as a small HTML fragment for the helpdesk UI.

my $cgi = CGI->new;

my $ticket_id      = $cgi->param('ticket_id');
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

print $cgi->header('text/html');
print "<html><head><title>Ticket View</title></head><body>\n";

my $status_badge = build_status_badge($ticket_id);

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print $ticket_html;

print "</body></html>\n";

sub build_status_badge {
    my ($id) = @_;
    return "<span class='badge'>Open</span>" if defined $id;
    return "<span class='badge'>Unknown</span>";
}
```

## Explanation

`$ticket_subject` and `$customer_reply` are attacker-controlled request parameters that were spliced into the HTML fragment as raw string concatenation, so any HTML/script metacharacters they contain (`<`, `>`, `&`, quotes) were emitted verbatim into the response and interpreted by the browser as markup rather than text. The fix wraps both values in `HTML::Entities::encode_entities()` (imported via `use HTML::Entities qw(encode_entities);`) at the point they are inserted into `$ticket_html`, which is the HTML-body/attribute output context here - both values sit inside element text content (`<h2>...</h2>`, a `<div>...</div>`) and the ticket markup itself uses single-quoted attributes elsewhere (`class='ticket'`, `class='reply'`), so `encode_entities()`'s default character set (which unconditionally escapes `<`, `>`, `&`, `"`, and `'`) is sufficient without needing a custom character list. This converts any markup the values contain into inert text (e.g. `<script>` becomes `&lt;script&gt;`) while leaving the surrounding template markup and the `$status_badge` value (which is not attacker-controlled) untouched.

## Behaviour changes

- Values containing `<`, `>`, `&`, `"`, or `'` are now rendered as their HTML entity equivalents instead of raw characters - this is the intended effect of the fix, not a side effect. Legitimate content containing those characters (e.g. a subject line with an ampersand) still displays correctly to the end user; only its literal browser-DOM interpretation changes from "parsed as markup" to "displayed as text".
- No other change: argument lists, return values, headers, control flow, and the `build_status_badge()` output are all unchanged from the original.

**Verification**: `perl -c` (with a minimal stub `CGI.pm` in `@INC`, since the CPAN `CGI` module is not installed in this environment and the original file fails the same `-c` check for the same reason before any fix is applied) reported `syntax OK` for the fixed file. Additionally ran the fixed script under Perl with a stub `CGI->param()` returning `<script>alert(1)</script>` for `subject` and `Hi & "quoted" <b>bold</b>` for `reply`: output showed both fully entity-encoded (`&lt;script&gt;alert(1)&lt;/script&gt;`, `Hi &amp; &quot;quoted&quot; &lt;b&gt;bold&lt;/b&gt;`) with no unescaped markup, confirming both the payload is neutralized and legitimate special characters still render (as encoded text) rather than being stripped.

**Assumptions**: `HTML::Entities` is a widely available CPAN module named directly by `cwe/79/perl/INDEX.md`; no version constraint is given in the guidance, and none is asserted here - confirm the resolved version via the project's dependency manifest/SCA tooling before merging.
