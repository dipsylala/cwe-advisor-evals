## Verdict

CWE-79 (Cross-Site Scripting) - **exploitable**. Confidence: high.

- **Location**: `DjangoMarkSafeMisuse.py`, line 23 (`mark_safe(banner_markup)` inside `build_announcement_html`)
- **Source**: `request.POST.get("announcement", "")` in `event_announcement_view` (line 8)
- **Sink**: `mark_safe(banner_markup)` (line 23)

## Source

`request.POST.get("announcement", "")` reads an attacker-controlled, organizer-submitted POST field. The only transformation applied before it reaches the sink is `.strip()` (line 11), which removes leading/trailing whitespace and performs no HTML neutralization. The value then flows unchanged into `build_announcement_html`, is interpolated with `"<div class='announcement'>{0}</div>".format(announcement_text)`, and the resulting markup is wrapped in `mark_safe()`, which tells Django's template engine to render it without auto-escaping. Since `mark_safe()` is applied to attacker-controlled content with no encoding step in between, the path is exploitable: a value such as `<script>...</script>` or an `<img onerror=...>` payload passed in the `announcement` field is rendered verbatim into the page and executes in the victim's browser.

## Fix

Vulnerable code:

```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    # SAST FINDING: CWE-79 reported here. Sink is the next statement.
    return mark_safe(banner_markup)
```

Fixed code:

```python
import html

from django.shortcuts import render
from django.utils.safestring import mark_safe


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

`build_announcement_html` assembles HTML manually by string interpolation rather than through an auto-escaping template, so this is the "non-template context" case the knowledge base calls out: the fix is `html.escape()` on the untrusted value at the point it is interpolated, not removal of `mark_safe()`. `html.escape(announcement_text)` converts `<`, `>`, `&`, `'`, and `"` to their HTML entity equivalents, so any markup or attribute-breakout payload in the announcement text is rendered as inert visible text instead of being parsed as HTML. `mark_safe()` is kept on the final assembled string because the surrounding `<div class='announcement'>...</div>` markup is developer-authored, trusted structure - escaping is applied only to the untrusted fragment before it is placed inside that structure, matching the "escape at the sink, wrap trusted structure" pattern rather than double-escaping the whole banner or breaking the intended markup.

## Behaviour changes

- Announcement text containing HTML metacharacters (`<`, `>`, `&`, `'`, `"`) is now rendered as visible escaped text (e.g. `&lt;b&gt;`) instead of being interpreted as markup. This is the fix itself, not an incidental change - it is what closes the injection.
- Return type and value are otherwise unchanged: `build_announcement_html` still returns a `SafeString` produced by `mark_safe()`, wrapped in the same `<div class='announcement'>` structure, so `event_announcement_view` and the template that renders `context["announcement"]` require no changes.
- No arguments, return values, or control flow were added, removed, or reordered beyond the one `html.escape()` call.
