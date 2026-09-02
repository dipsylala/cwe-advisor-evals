## Verdict

exploitable

## Source

`$cgi->param('note')` (line 18) - CGI query/form parameter, attacker-controlled.

## Fix

Vulnerable code:

```perl
# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

Fixed code:

```perl
use CGI;
use HTML::Entities;
...
print "<p>Customer note: " . encode_entities($cgi->param('note')) . "</p>\n";
```

Add `use HTML::Entities;` to the module imports at the top of the file alongside the existing `use CGI;`.

## Explanation

`$cgi->param('note')` returns the raw, attacker-controlled value of the `note` request parameter, which is concatenated directly into the HTML response body at line 18 with no encoding. An attacker can submit a `note` value such as `<script>...</script>` and have it execute in the victim's browser when the page renders. The fix wraps the value in `HTML::Entities::encode_entities()` before concatenation, converting `<`, `>`, `&`, `"`, and `'` into their HTML entity equivalents so the data is rendered as inert text rather than parsed as markup. This is an HTML-body text context (not an attribute or script block), so `encode_entities()`'s default entity set is the correct, sufficient encoding here; the knowledge base's caveat about `CGI.pm`'s `escapeHTML()` under-escaping a single quote in older versions does not apply since that function isn't used in the fix.

## Behaviour changes

- Non-alphanumeric characters in the `note` value (`<`, `>`, `&`, `"`, `'`) now render in the page as their literal characters via HTML entities instead of being interpreted as markup - this is the intended effect of the fix and is not a regression; a note like `Order & Ship <ASAP>` now displays correctly as literal text instead of `Ship` being swallowed by a broken tag.
- No other output, return value, or control flow is altered.
- Assumption: the finding is scoped to line 18 (`note` parameter) only, per the reported sink. Line 14 renders `$ticket_id` (from `$cgi->param('ticket_id')`) with the same unencoded pattern and shares the identical weakness, but it is outside the reported finding's location and was left unmodified to keep the fix surgical to the reported line; it should be flagged separately for the same remediation.
