## Verdict
exploitable

## Source
`request.POST.get("announcement", "")` at line 8 — untrusted user input from POST request

## Fix

**Vulnerable code:**
```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return mark_safe(banner_markup)
```

**Fixed code:**
```python
import html

def build_announcement_html(announcement_text):
    escaped_text = html.escape(announcement_text)
    banner_markup = "<div class='announcement'>{0}</div>".format(escaped_text)
    return mark_safe(banner_markup)
```

## Explanation

The vulnerability occurs because untrusted user input from `request.POST.get("announcement", "")` is directly interpolated into an HTML string without encoding, then marked as safe with `mark_safe()`, which disables Django's auto-escaping. This allows attackers to inject malicious scripts such as `<img src=x onerror="alert(1)">` that execute in the victim's browser.

The fix uses `html.escape()` from Python's standard library to encode special characters (`<`, `>`, `&`, `"`, `'`) as HTML entities before inserting the user input into the HTML string. This transforms the malicious payload into a literal string representation that the browser displays as text rather than executes as code. The `mark_safe()` call now correctly marks the resulting properly-escaped HTML as safe for rendering.

## Behaviour changes

none — The function still returns a SafeString suitable for rendering in Django templates, but now with proper encoding of user input. Display of the announcement text remains functionally identical except that special characters are safely rendered as entities rather than interpreted as HTML.
