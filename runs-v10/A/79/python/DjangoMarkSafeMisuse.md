## Verdict

This is a confirmed Cross-Site Scripting (CWE-79) vulnerability. User-controlled input from `request.POST.get("announcement", "")` is directly interpolated into an HTML string and then marked as safe without any escaping, allowing an attacker to inject arbitrary JavaScript.

## Source

User input enters via line 8:
```
announcement_text = request.POST.get("announcement", "")
```

This POST parameter is only whitespace-trimmed (line 11) and then directly embedded into HTML markup (line 21) without sanitization.

## Fix

Import `escape` from `django.utils.html` and apply it to the user-controlled text before constructing the HTML:

```python
from django.shortcuts import render
from django.utils.safestring import mark_safe
from django.utils.html import escape


def event_announcement_view(request):
    """Renders an organizer-submitted announcement banner on the event page."""
    organizer_name = request.user.get_full_name()
    announcement_text = request.POST.get("announcement", "")

    # Trim whitespace so the banner doesn't show a leading/trailing gap.
    announcement_text = announcement_text.strip()

    context = {
        "organizer_name": organizer_name,
        "announcement": build_announcement_html(announcement_text),
    }
    return render(request, "events/announcement_banner.html", context)


def build_announcement_html(announcement_text):
    escaped_text = escape(announcement_text)
    banner_markup = "<div class='announcement'>{0}</div>".format(escaped_text)
    return mark_safe(banner_markup)
```

## Explanation

The vulnerability exists because `mark_safe()` tells Django's template engine that the string is already safe HTML and should not be escaped during rendering. However, when user input is directly embedded into the HTML before calling `mark_safe()`, any HTML/JavaScript characters in the input will be interpreted as code, not text.

The fix applies `escape()` to the user-controlled text, which converts dangerous characters (`<`, `>`, `"`, `'`, `&`) into their HTML entity equivalents (`&lt;`, `&gt;`, etc.). This ensures that if an attacker submits `<script>alert('xss')</script>`, it will be rendered as literal text in the page rather than as executable JavaScript.

By escaping the input before marking the constructed HTML as safe, we create a boundary between untrusted user data (which is escaped) and the trusted structure of the HTML template (the `<div class='announcement'>` wrapper, which is marked safe).
