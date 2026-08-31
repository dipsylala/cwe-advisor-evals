## Verdict
Confirmed CWE-79 vulnerability. User-supplied input from `request.POST` is unsafely marked as safe HTML without sanitization.

## Source
Line 8 retrieves untrusted input: `announcement_text = request.POST.get("announcement", "")`. This value flows through string formatting on line 21 into raw HTML markup, then is explicitly marked safe on line 23 with `mark_safe()`, bypassing Django's template auto-escaping.

## Fix
Import `escape` from `django.utils.html` and apply it to the user input before interpolating into markup:

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
    banner_markup = "<div class='announcement'>{0}</div>".format(escape(announcement_text))
    return mark_safe(banner_markup)
```

Apply `escape()` to `announcement_text` before string formatting on line 21. This HTML-encodes special characters (`<`, `>`, `"`, `'`, `&`) so user input renders as literal text rather than executable markup.

## Explanation
`mark_safe()` is necessary to prevent Django's template layer from double-escaping intentional HTML structure, but it must only be called after user input has been neutralized. The vulnerability arises because the function trusts the input stream without escaping it first. `escape()` converts dangerous metacharacters to entity references, so `<script>` becomes `&lt;script&gt;` and displays as text rather than executing. The `mark_safe()` call on the final string is then safe because only the application-controlled markup structure remains unescaped.
