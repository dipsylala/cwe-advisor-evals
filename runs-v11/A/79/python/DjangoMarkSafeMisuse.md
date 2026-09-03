## Verdict

CWE-79 confirmed. User-controlled input from `request.POST.get("announcement")` flows unsanitized into HTML markup and is explicitly marked as safe for rendering, bypassing Django's auto-escaping protection.

## Source

Line 8: `announcement_text = request.POST.get("announcement", "")` reads untrusted input.

Line 21: User input is interpolated into HTML via string formatting: `banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)`.

Line 23: The markup is marked as safe without sanitization: `return mark_safe(banner_markup)`.

## Fix

Remove the `mark_safe()` call and return the markup directly. Django's template auto-escaping will neutralize any HTML metacharacters in `announcement_text`:

```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    return banner_markup
```

## Explanation

`mark_safe()` tells Django to trust the string and render it without escaping. This is dangerous when the string contains user input, even if that input has only been stripped of whitespace. An attacker can inject `<script>`, event handlers (`onerror`, `onclick`), or other HTML tags that execute in the victim's browser.

The fix removes the explicit trust marker. When the template receives `banner_markup`, Django's default auto-escaping converts special characters (`<`, `>`, `"`, `'`, `&`) to HTML entities, rendering them harmless. An attacker's `<img src=x onerror=alert(1)>` becomes `&lt;img src=x onerror=alert(1)&gt;`, displaying as literal text rather than executing.

If the application requires supporting HTML markup in user announcements in the future, use a dedicated sanitization library like `bleach` to allow specific safe tags while filtering dangerous ones, then mark only the sanitized output as safe.
