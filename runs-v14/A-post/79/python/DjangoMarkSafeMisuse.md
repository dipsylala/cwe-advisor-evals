## Verdict

Real XSS vulnerability. `mark_safe()` is applied to user-controlled input without sanitization, bypassing Django's HTML escaping and allowing arbitrary script injection.

## Source

User input from `request.POST.get("announcement", "")` (line 8) flows into string formatting at line 21, then is marked as safe at line 23 without any neutralization. An attacker can inject `<script>alert('XSS')</script>` or event handlers like `onload=` and the code will render them verbatim to the page.

## Fix

Remove the `mark_safe()` call. Let Django's template engine handle escaping:

```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    return banner_markup
```

Then in the template `events/announcement_banner.html`, render the value normally:

```django
{{ announcement }}
```

Django will automatically escape the HTML-unsafe characters, converting `<` to `&lt;`, `>` to `&gt;`, and so on, so any injected script tags become harmless display text.

## Explanation

`mark_safe()` tells Django "I have already made this string safe for rendering; do not escape it." When that string contains unfiltered user input, you have created an XSS vulnerability. The fix is to either remove `mark_safe()` entirely and rely on Django's default template auto-escaping, or—if you have a legitimate reason to mark the string as safe (e.g., because it contains trusted, formatted HTML)—use `django.utils.html.escape()` to sanitize the user input before formatting it. The simplest and most idiomatic fix in Django is to let the template engine escape the output for you, because that is what it does by default.
