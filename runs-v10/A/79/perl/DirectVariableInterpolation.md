## Verdict

**Confirmed.** The vulnerability is real. User-controlled input from `$cgi->param()` is directly interpolated into an HTML string without escaping, enabling XSS injection via the `guest_name` or `event_title` parameters.

## Source

```perl
my $guest_name  = $cgi->param('guest_name');
my $event_title = $cgi->param('event_title');

print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

Both parameters flow from untrusted input (HTTP request) directly into HTML output without sanitization.

## Fix

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI qw(escapeHTML);

# RSVP confirmation page for a company event signup form.
sub rsvp_confirmation {
    my $cgi = CGI->new;

    my $guest_name  = $cgi->param('guest_name');
    my $event_title = $cgi->param('event_title');

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    print "<h2>Thanks, " . escapeHTML($guest_name) . "! You're confirmed for " . escapeHTML($event_title) . ".</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation

HTML special characters in `$guest_name` and `$event_title` must be encoded before output. The `escapeHTML()` function from `CGI` converts `<`, `>`, `&`, `"`, and `'` to their corresponding HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting injected markup or scripts as code. Import the function explicitly in the `use CGI` statement and apply it to both parameters. String concatenation with `.` is used instead of interpolation to apply escaping selectively to the variable values.

