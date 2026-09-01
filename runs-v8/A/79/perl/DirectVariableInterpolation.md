## Verdict

Real vulnerability. User-controlled parameters are interpolated directly into HTML output without escaping, allowing arbitrary HTML/JavaScript injection.

## Source

```perl
my $guest_name  = $cgi->param('guest_name');
my $event_title = $cgi->param('event_title');

print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

The attacker can supply `guest_name` as `<img src=x onerror=alert(1)>` or `event_title` containing JavaScript, and the code will output it verbatim into the HTML.

## Fix

```perl
use CGI qw(escapeHTML);

my $guest_name  = escapeHTML($cgi->param('guest_name'));
my $event_title = escapeHTML($cgi->param('event_title'));

print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

Alternatively:

```perl
my $guest_name  = CGI::Util::html_escape($cgi->param('guest_name'));
my $event_title = CGI::Util::html_escape($cgi->param('event_title'));

print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

## Explanation

Escaping user input at the point of output converts special HTML characters to entities (`<` becomes `&lt;`, `"` becomes `&quot;`, `&` becomes `&amp;`, etc.), preventing the browser from interpreting user data as markup or script code. CGI's `escapeHTML()` is the standard defense for this pattern in Perl CGI scripts. The escaping must happen before the value is interpolated into the print statement, ensuring all untrusted data is neutralized before reaching the browser.
