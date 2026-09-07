## Verdict
CONFIRMED

## Source
Lines 10-11 read user input from CGI parameters `guest_name` and `event_title` without sanitization. These values flow directly into HTML output at line 18.

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

    # HTML-escape user input before rendering to HTML
    my $escaped_guest_name  = CGI::escapeHTML($guest_name);
    my $escaped_event_title = CGI::escapeHTML($event_title);

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    print "<h2>Thanks, $escaped_guest_name! You're confirmed for $escaped_event_title.</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation
The fix introduces HTML entity encoding for the untrusted user input before it is rendered into the HTML response. The `CGI::escapeHTML()` function converts special characters (`<`, `>`, `&`, `"`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), preventing the browser from interpreting attacker-supplied markup or JavaScript as code. This converts any potential script injection payload into harmless text that displays literally in the HTML output.

The new variables `$escaped_guest_name` and `$escaped_event_title` carry the sanitized values through to the output, ensuring all user-controlled data rendered to the response body is properly escaped.
