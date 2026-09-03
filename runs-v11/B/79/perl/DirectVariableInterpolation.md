## Verdict
exploitable

## Source
Line 10-11: `$cgi->param('guest_name')` and `$cgi->param('event_title')` return untrusted user input from CGI parameters.

## Fix

**Vulnerable code (line 18):**
```perl
print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

**Fixed code:**
```perl
use HTML::Entities;

# At the top of the file, add the import. Then update line 18:
print "<h2>Thanks, " . encode_entities($guest_name) . "! You're confirmed for " . encode_entities($event_title) . ".</h2>\n";
```

Alternatively, escape the values at their point of use:
```perl
use HTML::Entities;

my $guest_name  = $cgi->param('guest_name');
my $event_title = $cgi->param('event_title');

# ... 

my $safe_guest_name  = encode_entities($guest_name);
my $safe_event_title = encode_entities($event_title);

print "<h2>Thanks, $safe_guest_name! You're confirmed for $safe_event_title.</h2>\n";
```

## Explanation
The vulnerability allows attackers to inject malicious JavaScript via the `guest_name` or `event_title` parameters. For example, an attacker could submit `<script>alert('XSS')</script>` as the guest_name, which would execute in the victim's browser. The fix applies HTML encoding using `HTML::Entities::encode_entities()` to escape special characters (`<`, `>`, `&`, `"`) before rendering them in the HTML response. This ensures that user-controlled data remains data and cannot be interpreted as executable code. The encoding must occur at the output sink, not on input, because the same value may be rendered into different contexts (HTML body, attributes, JavaScript) where different encoding is required.

## Behaviour changes
none
