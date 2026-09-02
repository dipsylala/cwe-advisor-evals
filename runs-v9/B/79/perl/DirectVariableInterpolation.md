## Verdict

Exploitable. `guest_name` and `event_title` are read directly from the request via `CGI->param()` and interpolated into the HTML response at line 18 with no encoding, validation, or escaping of any kind. A request containing `guest_name=<script>alert(document.cookie)</script>` renders that markup verbatim in the response body, giving reflected XSS.

## Source

`$cgi->param('guest_name')` and `$cgi->param('event_title')` (lines 10-11) - both are attacker-controlled CGI request parameters, read via CGI.pm's `param()`.

## Fix

Vulnerable code:

```perl
    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

Fixed code:

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities;

# RSVP confirmation page for a company event signup form.
sub rsvp_confirmation {
    my $cgi = CGI->new;

    my $guest_name  = $cgi->param('guest_name');
    my $event_title = $cgi->param('event_title');

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    my $safe_guest_name  = encode_entities($guest_name);
    my $safe_event_title = encode_entities($event_title);

    print "<h2>Thanks, $safe_guest_name! You're confirmed for $safe_event_title.</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

Library recommendation: `HTML::Entities` (core-adjacent, widely bundled, ships on CPAN as part of the `HTML-Parser` distribution). The knowledge base guidance does not carry a minimum safe version for this library, so none is supplied here - confirm the resolved version against SCA/dependency-check tooling before merging.

## Explanation

Both request parameters were interpolated straight into the HTML response body with no output encoding, letting an attacker break out of the text node and inject markup or script. The fix passes each value through `HTML::Entities::encode_entities()` immediately before it is used in the HTML output, converting `<`, `>`, `&`, `"`, and `'` (and other HTML-significant characters, since no second argument restricting the character set was supplied) into their entity forms. The values become inert text in the `<h2>` element regardless of content, closing the injection point at the point of output rather than relying on input-side filtering, which the guidance identifies as easy to bypass.

## Behaviour changes

- Added `use HTML::Entities;` - new dependency required to perform the encoding; not previously imported.
- Introduced `$safe_guest_name` and `$safe_event_title` holding the encoded values, used only in the line 18 print statement in place of the raw `$guest_name`/`$event_title`. The original variables are otherwise unused downstream, so no other code path is affected.
- Output text changes only when `guest_name` or `event_title` contains `<`, `>`, `&`, `"`, or `'` (or another character in `encode_entities()`'s default set): those characters now render as HTML entities instead of raw characters. This is the intended effect of the fix - the displayed text is unchanged for ordinary names/titles, and the entity-encoded form still displays correctly to the browser.
- `print $cgi->header(...)`, the `<!DOCTYPE>`/`<html>` boilerplate, and the closing markup are untouched. No change to return value, error handling, or the sink's argument list beyond the two values now being pre-encoded strings rather than raw request data.
