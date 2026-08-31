## Verdict

**Confirmed.** Untrusted user input from `request.POST.get("announcement", "")` is formatted directly into HTML without escaping and then explicitly marked as safe, disabling Django's protection and allowing arbitrary HTML/JavaScript execution.

## Source

Line 8: `announcement_text = request.POST.get("announcement", "")` provides attacker-controlled input.

Line 11: `announcement_text.strip()` removes only whitespace; it does not sanitize HTML.

Line 21: `banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)` inserts the untrusted value directly into HTML.

Line 23: `mark_safe(banner_markup)` is the sink that disables all escaping.

## Fix

```python
import html
from django.shortcuts import render


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
    # Escape untrusted input to prevent XSS; no mark_safe() needed for escaped content
    escaped_text = html.escape(announcement_text)
    banner_markup = "<div class='announcement'>{0}</div>".format(escaped_text)
    return banner_markup
```

Changes:
1. Added `import html` at the top
2. Wrapped untrusted `announcement_text` with `html.escape()` before formatting into HTML
3. Removed `mark_safe()` call since the static HTML structure is safe and the user content is now escaped

## Explanation

The vulnerability occurs because `mark_safe()` tells Django "trust this HTML string completely" and bypasses all auto-escaping for that value. Untrusted user input formatted into the string is then treated as executable code. An attacker submitting `<script>alert('xss')</script>` or `" onload="alert('xss')"` will have their payload execute in the victim's browser.

The fix uses `html.escape()` to convert special characters (`<`, `>`, `&`, `"`, `'`) into HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the browser from interpreting them as markup or JavaScript. The static HTML structure (`<div class='announcement'>` and `</div>`) remains unescaped because it is not user-controlled. Removing `mark_safe()` is safe because the content is now properly encoded.

## Behaviour changes

For legitimate input containing no special characters, the output is identical. For input containing HTML metacharacters (e.g., `"Hello <world>"` submitted by a user), the output changes from:

```html
<div class='announcement'>Hello <world></div>
```

to:

```html
<div class='announcement'>Hello &lt;world&gt;</div>
```

The user's text renders as-is in the browser (displaying the literal `<` and `>` characters) rather than being interpreted as an unclosed tag. This is correct behavior for user-submitted text and is what the user expects to see.
