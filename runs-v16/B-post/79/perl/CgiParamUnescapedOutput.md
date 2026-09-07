## Verdict

Exploitable.

## Source

`$cgi->param('note')` at line 10 (parameter retrieval) flows through line 18 (output).

The CGI parameter `note` returns untrusted user input from the HTTP request.

## Fix

**Vulnerable code (line 18):**

```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

**Fixed code:**

```perl
use HTML::Entities;

...

print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

Add `use HTML::Entities;` near the top of the file (after the existing `use` statements on lines 2-4).

## Explanation

The vulnerability occurs because `$cgi->param('note')` returns untrusted user input directly concatenated into an HTML string and printed without any encoding. An attacker can inject XSS payloads like `<script>alert(1)</script>` or `" onmouseover="alert(1)"`, which will be interpreted and executed as code in the victim's browser.

The fix wraps the untrusted parameter value with `encode_entities()` from the standard `HTML::Entities` module, which encodes special HTML characters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This ensures the data remains data rather than executable code. The encoding is applied at the output sink, which is the correct location according to CWE-79 remediation guidance.

## Behaviour changes

- Special characters in the customer note (`<`, `>`, `&`, `"`, `'`) are now encoded as HTML entities and will display as entities in the browser (e.g., `&lt;` instead of `<`). This is correct behaviour for HTML body text context and does not affect legitimate user input.
- The `print` statement output is now HTML-safe; malicious payloads are neutralized because they are rendered as visible text rather than executable markup.
- No changes to the call signature, return values, or control flow of the code beyond the encoding wrapper.
