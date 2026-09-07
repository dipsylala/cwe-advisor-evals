## Verdict

Exploitable. The user-controlled `note` parameter is rendered directly into HTML output without encoding, allowing XSS injection.

## Source

Line 10: `my $ticket_id = $cgi->param('ticket_id');` and Line 18: `$cgi->param('note')` - both receive untrusted user input from CGI parameters. The `ticket_id` parameter on line 14 is also unencoded in HTML output, but the reported finding is on line 18.

## Fix

**Vulnerable code (line 18):**
```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

**Fixed code:**
```perl
use HTML::Entities;

# ... existing code ...

print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

The `use HTML::Entities;` statement should be added at the top of the file with the other imports (after line 4).

## Explanation

The original code concatenates the user-supplied `note` parameter directly into HTML output without encoding special characters. An attacker can inject JavaScript through the `note` parameter (e.g., `<script>alert('XSS')</script>` or `" onmouseover="alert('XSS')`), which will execute in the victim's browser. The fix uses `HTML::Entities::encode_entities()` to convert dangerous HTML characters (`<`, `>`, `&`, `"`, `'`) into entity references (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring the user input is rendered as text data rather than executable code. This is the standard Perl pattern for HTML context output encoding.

## Behaviour changes

- **New import:** `use HTML::Entities;` adds a dependency on the HTML::Entities module (part of standard Perl distributions).
- **Output encoding:** Special characters in the `note` parameter will now be HTML-encoded. For example, `<script>` becomes `&lt;script&gt;`, which renders as literal text `<script>` in the browser rather than being interpreted as HTML/JavaScript.
- **User experience:** If legitimate content contains HTML special characters (e.g., mathematical symbols with `<`, email addresses with `&`), they will display correctly as text. Users who intentionally include markup in notes will see the markup as literal text rather than being processed as HTML.
- **No functional regression:** The fix preserves the original behavior of displaying the customer note; it only changes how special characters are handled to prevent code execution.
