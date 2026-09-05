## Verdict
Exploitable

## Source
Line 8: `announcement_text = request.POST.get("announcement", "")` — untrusted user input from POST parameter

## Fix

**Vulnerable code (line 20-23):**
```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return mark_safe(banner_markup)
```

**Fixed code:**
```python
import html
from django.utils.safestring import mark_safe

def build_announcement_html(announcement_text):
    # Escape user input to prevent XSS before building HTML structure
    escaped_text = html.escape(announcement_text)
    banner_markup = "<div class='announcement'>{0}</div>".format(escaped_text)
    return mark_safe(banner_markup)
```

## Explanation
The vulnerability occurs because `announcement_text` — untrusted user input from `request.POST` — is inserted directly into HTML without encoding, then passed to `mark_safe()` which disables Django's autoescaping. An attacker can inject `<script>` tags or event handlers (e.g., `<img onerror="alert('XSS')">`) that execute in victims' browsers.

The fix escapes the untrusted input using `html.escape()` before inserting it into the HTML structure. This replaces HTML metacharacters (`<`, `>`, `&`, `"`) with their entity equivalents, preventing the injected content from being interpreted as HTML tags or attributes. The `mark_safe()` call remains appropriate because the HTML structure itself is controlled by the application and only the user input is escaped.

## Behaviour changes
None. The `mark_safe()` call still returns a `SafeString` that Django's template engine will not re-escape. The difference is that `announcement_text` is first escaped, so its special characters are neutralized before the string is marked safe. Legitimate content containing `<`, `>`, `&`, or quotes will now appear as text in the banner rather than being interpreted as HTML markup, which is the correct and intended behavior.
