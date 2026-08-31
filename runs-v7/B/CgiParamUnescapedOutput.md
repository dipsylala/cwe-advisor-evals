## Verdict

Exploitable. The `note` parameter is read from untrusted user input via `$cgi->param('note')` and output directly into HTML body context without encoding on line 18, allowing XSS injection.

## Source

`$cgi->param('note')` on line 18 — CGI query parameter, untrusted user input.

## Fix

**Vulnerable code:**
```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

**Fixed code:**
```perl
use HTML::Entities;

# ... later in the script ...

print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

## Explanation

The fix applies HTML entity encoding to the user-supplied `note` parameter using `HTML::Entities::encode_entities()`. This converts special characters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), ensuring they are treated as text content rather than executable code. This prevents script injection while preserving the legitimate note text — a payload like `<script>alert(1)</script>` is rendered harmlessly as visible text rather than executed.

## Behaviour changes

- Added `use HTML::Entities;` import statement (required once at the top of the script).
- The output content remains functionally identical for legitimate notes, but special HTML characters are now escaped. This is the intended and correct behaviour — the user's data is preserved, but sanitized for safe rendering in HTML.
