## Verdict
CONFIRMED

## Source
Line 18 interpolates user-controlled variables `$guest_name` and `$event_title` directly into HTML output without escaping. These values originate from `CGI->param()` calls on lines 10-11, which return untrusted user input. If an attacker supplies HTML/JavaScript in these parameters, it executes in the victim's browser.

## Fix

### File: DirectVariableInterpolation.pl

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

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    print "<h2>Thanks, " . encode_entities($guest_name) . "! You're confirmed for " . encode_entities($event_title) . ".</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation
The fix adds `use HTML::Entities` and wraps the vulnerable interpolations with `encode_entities()` calls. This function converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting user input as HTML or script code. The encoded values render as visible text in the page, preserving the user's intent while blocking injection attacks.
