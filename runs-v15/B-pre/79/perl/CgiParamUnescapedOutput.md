## Verdict

VULNERABLE. The `note` parameter from user input is rendered directly into HTML without encoding on line 18, allowing Cross-Site Scripting (XSS) injection.

## Source

Line 18 sources untrusted user input via `$cgi->param('note')` and renders it directly into HTML context without any encoding:

```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

An attacker can inject XSS payloads through the `note` query parameter (e.g., `?note=<script>alert(1)</script>`), which will execute in the victim's browser when the page is rendered.

## Fix

Use `HTML::Entities::encode_entities()` to escape the user input before rendering it into HTML:

```perl
use HTML::Entities;

print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

Add the `use HTML::Entities;` import at the top of the file with the other use statements (after line 4). Replace line 18 with the version that calls `encode_entities()` on the untrusted parameter.

## Explanation

`HTML::Entities::encode_entities()` converts dangerous HTML characters (`<`, `>`, `&`, `"`, `'`) into their entity-safe equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), so that user-supplied content is rendered as text rather than executable HTML. This prevents the browser from interpreting injected script tags or event attributes as code. The encoding is applied at the output sink (the print statement), which is the appropriate location to enforce context-specific neutralization. `HTML::Entities` is a standard Perl module and has no security-related version constraints for this fix.

## Behaviour changes

- User-supplied note content containing characters like `<`, `>`, `&`, or quotes will now render as escaped entities visible to the user (e.g., `<script>` displays as `&lt;script&gt;`), which is the correct and expected behaviour for displaying untrusted content in HTML.
- Legitimate content is preserved and displayed correctly; only the dangerous interpretation is blocked.
- No other behaviour is affected.
