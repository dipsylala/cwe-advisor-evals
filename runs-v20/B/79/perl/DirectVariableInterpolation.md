## Verdict

exploitable

- cwe_id: CWE-79
- location: `DirectVariableInterpolation.pl`, line 18 (sink)
- confidence: high

## Source

`$cgi->param('guest_name')` and `$cgi->param('event_title')` (lines 10-11) - both read directly from the incoming CGI request with no validation or encoding applied anywhere between the read and the print.

## Fix

### File: DirectVariableInterpolation.pl

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;

# RSVP confirmation page for a company event signup form.
sub rsvp_confirmation {
    my $cgi = CGI->new;

    my $guest_name  = $cgi->param('guest_name');
    my $event_title = $cgi->param('event_title');

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    print "<h2>Thanks, ", $cgi->escapeHTML($guest_name), "! You're confirmed for ", $cgi->escapeHTML($event_title), ".</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation

Line 18 interpolated `$guest_name` and `$event_title` straight into an HTML response with no encoding, so either CGI parameter could close the `<h2>` tag and inject a script (e.g. `guest_name=<script>alert(1)</script>`). The fix keeps the same `print` call and output structure but wraps each tainted value in `$cgi->escapeHTML()` before it reaches the sink, converting `<`, `>`, `&`, and `"` into their HTML entity equivalents so the values can only ever render as text inside the `<h2>` element, never as markup. `escapeHTML()` is the CGI.pm method already in scope via the existing `$cgi` object, so no new import is required; its one documented gap (inconsistent single-quote escaping on CGI.pm versions before 4.11) only matters when a value is placed inside a single-quoted HTML attribute, which is not the case here - both values are rendered as HTML body text, not attribute values, so that gap does not apply to this sink.

## Behaviour changes

- The single interpolated string literal on line 18 became a multi-argument `print` list (`"...", $cgi->escapeHTML($guest_name), "...", $cgi->escapeHTML($event_title), "...\n"`). Perl's `print` concatenates a list of arguments with no separator by default (`$,` is unset), so the emitted bytes are unchanged for any input that contains no HTML metacharacters - this is a mechanical restructuring to isolate the encoding calls, not a formatting change.
- Legitimate guest names or event titles containing `<`, `>`, `&`, or `"` (e.g. an event titled `R&D Kickoff`) now render as their escaped entities (`R&amp;D Kickoff`) instead of raw characters. This is the intended effect of closing the XSS weakness and is visually a no-op in a rendered browser.
- If a parameter is absent, `$cgi->param()` returns `undef` and `escapeHTML(undef)` also returns `undef`/empty, which `print`s as an empty string under `use warnings` (the same "Use of uninitialized value" warning the original code already produced by interpolating an undefined variable into a string). No new failure mode is introduced.
- No other change: same headers, same status output, same overall page structure, same function signature and return value (`return;`, undef).

## Verification

Ran `perl -c` against the fixed file. CGI.pm is not installed in this environment, so a minimal stub module (`new`, `param`, `header`, `escapeHTML`) was placed on `-I` to satisfy the `use CGI;` compile-time dependency; the real CGI.pm on CPAN exposes `escapeHTML` with the same instance-method signature used here. Result: `syntax OK`, no errors or warnings from the parse.

Assumptions: none of the ambiguity-resolution rules in Step 1/3 applied (CWE ID, language, and sink were all unambiguous from the finding and file extension).
