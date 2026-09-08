## Verdict

Confirmed: CWE-79 Cross-Site Scripting via `mark_safe()` on unescaped user input.

## Source

Line 8: `announcement_text = request.POST.get("announcement", "")` — attacker-controlled POST parameter.

## Fix

The user input must be escaped before being embedded in HTML markup and passed to `mark_safe()`. Replace the vulnerable function with proper HTML escaping using Python's standard library `html.escape()`.

### File: DjangoMarkSafeMisuse.py

```python
from django.shortcuts import render
from django.utils.safestring import mark_safe
import html


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
    escaped_text = html.escape(announcement_text)
    banner_markup = "<div class='announcement'>{0}</div>".format(escaped_text)
    return mark_safe(banner_markup)
```

## Explanation

The vulnerability occurs because user input from `request.POST.get("announcement")` is directly interpolated into HTML markup via `.format()` without escaping, then marked as safe with `mark_safe()`. This bypasses Django's template auto-escaping and allows an attacker to inject arbitrary HTML or JavaScript.

The fix introduces `html.escape()` from Python's standard library (no additional dependencies) to encode dangerous characters in the user input. Characters like `<`, `>`, and `&` are converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`), which prevents them from being interpreted as HTML or script tags. After escaping, the generated HTML markup is safe, and `mark_safe()` correctly identifies it as such. This preserves the intended div wrapper while preventing script injection.

## Behaviour changes

- User input containing `<`, `>`, `&`, and quotes will now be displayed as HTML entities (e.g., `<script>` renders as `&lt;script&gt;`) instead of being interpreted as HTML tags or script blocks.
- Legitimate content with special characters (e.g., "AT&T" or "cost < $100") will display correctly with entities visible as plain text, not as HTML constructs.
- No change to the structure or styling of the announcement banner HTML itself.
