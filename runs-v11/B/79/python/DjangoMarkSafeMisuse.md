## Verdict

Exploitable

## Source

Source: `request.POST.get("announcement", "")` at line 8 of `event_announcement_view()`

Sink: `mark_safe()` call at line 23 of `build_announcement_html()`

Data flow: User-submitted form data (untrusted) → passed through `event_announcement_view()` to `build_announcement_html()` → inserted via `.format()` into HTML string (line 21) → wrapped with `mark_safe()` which disables Django's auto-escaping

## Fix

**Vulnerable code (lines 20-23):**

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

The vulnerability occurs because `announcement_text` from `request.POST` (untrusted user input) is directly inserted into HTML markup via string formatting on line 21, then passed through `mark_safe()` on line 23 which disables Django's auto-escaping. An attacker can inject malicious scripts such as `<script>alert('XSS')</script>` which will execute in victims' browsers.

The fix applies `html.escape()` from Python's standard library to the user input before it is inserted into the HTML string. This escapes HTML special characters (`<`, `>`, `&`, `"`) into their entity representations, preventing the input from being interpreted as HTML or JavaScript code. The wrapper div structure is still marked safe since it is static HTML constructed entirely by the application, not derived from user input.

## Behaviour changes

None. The fix preserves the sink contract: `mark_safe()` still returns a `SafeString` object that Django templates will not re-escape, and the function still returns properly formatted HTML markup with the announcement text displayed inside a div with the `announcement` CSS class. The only change is that user-controlled content is now properly escaped before being marked safe, which eliminates the injection vector while maintaining all existing functionality.
