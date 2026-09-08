## Verdict

**Exploitable.** Untrusted user input from HTTP request parameters is directly interpolated into HTML output without encoding, allowing arbitrary JavaScript execution in the victim's browser.

## Source

- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **File:** DirectVariableInterpolation.pl, line 18
- **Vulnerable Code:** Direct interpolation of `$guest_name` and `$event_title` in HTML print statement

## Data Flow

1. **Source (untrusted):** Lines 10-11 - `$cgi->param('guest_name')` and `$cgi->param('event_title')` read directly from HTTP request parameters
2. **Transformation:** None - values pass through unmodified
3. **Sink (HTML context):** Line 18 - Raw interpolation into HTML body text via `print` statement

**Attack vector:** An attacker can set `guest_name=<img src=x onerror=alert(1)>` or `event_title=<script>alert(1)</script>` to inject executable JavaScript into the page.

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

The fix adds `use HTML::Entities;` at the top and wraps both user-supplied variables with `encode_entities()` before they are interpolated into the HTML output. The `encode_entities()` function converts special characters like `<`, `>`, `&`, and quotes to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring they are rendered as text rather than executed as markup or script.

This is the primary defence for XSS in HTML body and attribute contexts. The untrusted input becomes data that is safe to display, preventing script injection while preserving legitimate characters like spaces and hyphens in names and event titles.

## Behaviour changes

- Input containing `<`, `>`, `&`, `"`, and `'` will now be displayed as HTML entities rather than as markup
- Example: `guest_name="Alice & Bob"` will render as `Alice &amp; Bob` instead of `Alice & Bob` (visually identical to the user but safe)
- Example: `guest_name="<script>alert(1)</script>"` will render as `&lt;script&gt;alert(1)&lt;/script&gt;` (visible as text, not executed)
- Legitimate names and event titles render identically to users; the difference is only in the HTML source, where special characters are now encoded
