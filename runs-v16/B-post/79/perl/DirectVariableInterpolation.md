## Verdict

Exploitable. User-controlled input from HTTP request parameters flows directly into HTML output without encoding, enabling arbitrary JavaScript injection.

## Source

Untrusted data enters from CGI parameters on lines 10-11:
```
my $guest_name  = $cgi->param('guest_name');
my $event_title = $cgi->param('event_title');
```

These values come from the HTTP request and are not validated or constrained by the application.

## Fix

Add `use HTML::Entities;` at the top of the file (after line 4), then encode the input values at the point of retrieval:

**Vulnerable code:**
```perl
my $guest_name  = $cgi->param('guest_name');
my $event_title = $cgi->param('event_title');
```

**Fixed code:**
```perl
use HTML::Entities;

my $guest_name  = encode_entities($cgi->param('guest_name'));
my $event_title = encode_entities($cgi->param('event_title'));
```

The print statement on line 18 remains unchanged:
```perl
print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";
```

## Explanation

The vulnerability arises because `$guest_name` and `$event_title` are interpolated directly into the HTML output without encoding. An attacker can inject malicious JavaScript by providing input like `<script>alert('xss')</script>`, which the browser then executes when rendering the page.

The fix applies HTML entity encoding to both variables at the point where they receive untrusted data from the CGI parameters. The `HTML::Entities::encode_entities()` function converts dangerous characters (`<`, `>`, `"`, `'`, `&`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&amp;`). This ensures that any malicious markup in the input is rendered as literal text rather than executable code. Since the encoded values are assigned to the same variable names, all downstream uses—including the print statement on line 18—are automatically protected without requiring additional changes.

## Behaviour changes

None. The fix preserves the original contract:
- Input values are still retrieved from CGI parameters
- The same variables are used in the same print statement
- Output is still HTML text to the client
- Legitimate content containing `<`, `&`, and `"` still renders correctly (as their entity-encoded forms)
- No additional dependencies beyond HTML::Entities (a Perl core module)

Verification (Perl 5.24.1):
```
Syntax check: OK
HTML::Entities available: yes
Test output with <script>alert(1)</script>: &lt;script&gt;alert(1)&lt;/script&gt;
Test output with "quotes": &quot;quotes&quot;
```
