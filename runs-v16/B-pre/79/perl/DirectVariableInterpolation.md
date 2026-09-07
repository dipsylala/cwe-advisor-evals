## Verdict

Exploitable. Untrusted user input from `$cgi->param('guest_name')` and `$cgi->param('event_title')` flows directly into HTML output at line 18 via string interpolation without encoding, allowing arbitrary HTML/JavaScript injection.

## Source

Lines 10–11: CGI parameters obtained via `$cgi->param()`:
- `$guest_name` - user-supplied event attendee name
- `$event_title` - user-supplied event description

Both are untrusted external input with no validation or encoding applied.

## Fix

**Vulnerable code (line 18):**
```perl
print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

**Fixed code:**
```perl
use HTML::Entities;

sub rsvp_confirmation {
    my $cgi = CGI->new;

    my $guest_name  = $cgi->param('guest_name');
    my $event_title = $cgi->param('event_title');

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    # Encode untrusted input to prevent XSS
    my $safe_name  = encode_entities($guest_name);
    my $safe_title = encode_entities($event_title);
    print "<h2>Thanks, $safe_name! You're confirmed for $safe_title.</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}
```

## Explanation

The fix imports `HTML::Entities` and applies `encode_entities()` to both `$guest_name` and `$event_title` before they are interpolated into the HTML output. `encode_entities()` converts dangerous characters—`<`, `>`, `&`, and quotes—into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring that user-supplied content is treated as data rather than executable HTML/JavaScript code. The encoded values are assigned to fresh variables (`$safe_name` and `$safe_title`) to clearly separate trusted from untrusted data, and these trusted values are used in the output sink. This prevents injection attacks such as `<script>alert(1)</script>` or event handlers like `" onmouseover="alert(1)` from executing in the victim's browser.

## Behaviour changes

None. The output remains valid HTML; the only difference is that special characters in user input are entity-encoded so they render as literal text (e.g., `<script>` displays as `&lt;script&gt;`). The HTTP headers, page structure, and confirmation message functionality are unchanged. Legitimate content containing `<`, `&`, and quotes will render correctly after entity encoding.
