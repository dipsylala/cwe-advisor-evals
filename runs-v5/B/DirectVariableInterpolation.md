## Verdict

Exploitable. CWE-79 (Reflected Cross-Site Scripting).

- Location: `DirectVariableInterpolation.pl`, line 18 (the `print "<h2>...</h2>\n"` statement).
- Confidence: high.

## Source

`$cgi->param('guest_name')` and `$cgi->param('event_title')` (lines 10-11) - both read directly from the CGI request via `CGI->new`, with no validation, allowlisting, or encoding applied anywhere between the read and the sink.

## Fix

Vulnerable code:

```perl
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

    # SAST FINDING: CWE-79 reported here. Sink is the next statement.
    print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}
```

Fixed code:

```perl
use strict;
use warnings;
use CGI;
use HTML::Entities qw(encode_entities);

# RSVP confirmation page for a company event signup form.
sub rsvp_confirmation {
    my $cgi = CGI->new;

    my $guest_name  = $cgi->param('guest_name');
    my $event_title = $cgi->param('event_title');

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    print "<h2>Thanks, " . encode_entities($guest_name)
        . "! You're confirmed for " . encode_entities($event_title) . ".</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}
```

## Explanation

`guest_name` and `event_title` are attacker-controlled CGI parameters that were interpolated straight into an HTML body context with no encoding, letting a value like `<script>...</script>` break out of the text node and execute in the victim's browser. The fix wraps each value in `HTML::Entities::encode_entities()` at the point it is written into the HTML response, converting `<`, `>`, `&`, and quote characters to their HTML entity equivalents so the browser renders them as literal text rather than markup. This is the HTML-body-context encoding the language guidance calls for (`encode_entities()` from `HTML::Entities`); it was chosen over `CGI.pm`'s own `escapeHTML()` because pre-4.11 versions of `escapeHTML()` leave a single quote unescaped outside ISO-8859-1/Windows-1252 charsets, and this response is served as UTF-8, so `encode_entities()` avoids depending on the installed `CGI.pm` version for that guarantee.

## Behaviour changes

- Added `use HTML::Entities qw(encode_entities);` - required to call the encoding function; no runtime behaviour beyond the encoding itself.
- `guest_name` and `event_title` now render as their HTML-entity-encoded form (e.g. a literal `&` in a name becomes `&amp;`) instead of raw text. This only changes rendering for input containing `<`, `>`, `&`, `"`, or `'`; ordinary names and titles display identically. No other output, return value, or control flow was changed - the `print` calls, header, and function contract are otherwise unchanged.

Assumptions: none - both parameters are read from the same untrusted source and rendered in the same body-text context, so both required the identical fix.
