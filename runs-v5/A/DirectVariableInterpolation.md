## Verdict

Confirmed. `guest_name` and `event_title` are read from CGI request parameters (`$cgi->param(...)`) and interpolated directly into an HTML response string with no encoding, allowing reflected cross-site scripting.

## Source

```perl
my $guest_name  = $cgi->param('guest_name');
my $event_title = $cgi->param('event_title');
```

Both values come from `CGI->param()`, i.e. attacker-controlled query string or POST body data.

## Fix

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use CGI qw(escapeHTML);

# RSVP confirmation page for a company event signup form.
sub rsvp_confirmation {
    my $cgi = CGI->new;

    my $guest_name  = $cgi->param('guest_name');
    my $event_title = $cgi->param('event_title');

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    my $safe_guest_name  = escapeHTML($guest_name);
    my $safe_event_title = escapeHTML($event_title);

    print "<h2>Thanks, $safe_guest_name! You're confirmed for $safe_event_title.</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation

`CGI::escapeHTML` (imported via `use CGI qw(escapeHTML)`) HTML-entity-encodes the special characters `< > & " '`, so any markup or script tags submitted as `guest_name` or `event_title` are rendered as inert text instead of being parsed by the browser as HTML. The encoding is applied at the point of output, right before interpolation into the response string, which keeps the fix localized to the sink and ensures every value written into the page from these two parameters is neutralized regardless of what upstream validation does or does not do. `escapeHTML` is part of the standard `CGI` module already in use, so no new dependency is introduced. An equally valid alternative is `HTML::Entities::encode_entities`, but since the script already depends on `CGI`, reusing its built-in escaper keeps the change minimal.
