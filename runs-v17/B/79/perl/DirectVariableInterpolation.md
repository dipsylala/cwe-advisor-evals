## Verdict

exploitable

## Source

User input from `$cgi->param('guest_name')` and `$cgi->param('event_title')` (lines 10-11), both controlled by the request query parameters and untrusted.

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
    
    # Encode user input for HTML output
    my $safe_guest_name  = encode_entities($guest_name);
    my $safe_event_title = encode_entities($event_title);

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    print "<h2>Thanks, $safe_guest_name! You're confirmed for $safe_event_title.</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation

The vulnerability occurs because untrusted user input from `$guest_name` and `$event_title` is directly interpolated into HTML output on line 18 without any encoding. This allows an attacker to inject arbitrary HTML or JavaScript that executes in the victim's browser. The fix introduces HTML entity encoding using `HTML::Entities::encode_entities()`, which converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This ensures that user input remains data rather than executable code. The encoded values are stored in separate variables (`$safe_guest_name` and `$safe_event_title`) which are then used in the HTML output, following the principle of treating the original tainted values as read-only and using validated/encoded copies for all downstream output contexts.

## Behaviour changes

- Added `use HTML::Entities;` import (line 5) to enable context-appropriate HTML entity encoding
- Introduced two new scalar variables `$safe_guest_name` and `$safe_event_title` (lines 15-16) to hold the encoded values
- The interpolated values in the `print` statement (line 24) now use the encoded versions instead of the raw user input
- These changes preserve the function's return value and output format; the only change is that special HTML characters in user input are now escaped, preventing script injection while maintaining readability of legitimate content containing `<`, `>`, `&`, `"`, or `'`
