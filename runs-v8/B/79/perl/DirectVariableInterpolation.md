## Verdict

Real and exploitable. The variables `$guest_name` and `$event_title` are sourced from untrusted user input via CGI parameters and interpolated directly into HTML output without encoding, allowing an attacker to inject arbitrary HTML and JavaScript.

## Source

Lines 10-11: `$guest_name` and `$event_title` are obtained from CGI request parameters via `$cgi->param()` without validation or sanitization.

```
my $guest_name  = $cgi->param('guest_name');
my $event_title = $cgi->param('event_title');
```

## Fix

Apply HTML entity encoding to both variables before output using `HTML::Entities::encode_entities()`:

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

    # HTML encode both variables before interpolation into HTML context
    print "<h2>Thanks, " . encode_entities($guest_name) . "! You're confirmed for " . encode_entities($event_title) . ".</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
```

## Explanation

The fix adds `use HTML::Entities;` to import the encoding function and wraps both `$guest_name` and `$event_title` with `encode_entities()` before they are rendered into the HTML body context on line 18. This function converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring that attacker-supplied payloads like `<script>alert(1)</script>` or event handlers (`' onload='alert(1)`) are rendered as literal text rather than executable HTML/JavaScript. Output encoding at the sink is the primary defence against XSS, and context-aware encoding (HTML encoding for HTML body text) ensures the data remains data, not code, in the user's browser.

## Behaviour changes

- Valid input containing characters like `<`, `>`, `&`, `"`, or `'` will now be displayed as HTML entities in the browser's rendered output (e.g., `"Don't"` remains readable as `"Don't"` but is transmitted as `"Don&apos;t"`), not as unencoded characters. This is the expected and safe behaviour for user-controlled content in HTML contexts.
- Invalid/malicious input such as `<img src=x onerror=alert(1)>` will render safely as literal text in the page rather than executing as an HTML tag or script.
- The HTTP response body and Content-Type remain unchanged; the fix applies only to the interpolation of the two parameters.
