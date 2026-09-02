## Verdict

Confirmed. `build_announcement_html` interpolates the user-controlled `announcement_text` (from `request.POST.get("announcement", "")`) directly into an HTML string via `str.format`, then wraps the result in `mark_safe()`. This tells Django's template auto-escaper to render the markup verbatim, so any HTML/JavaScript an organizer submits in the `announcement` field is injected into the page unescaped and executes in every visitor's browser (stored XSS).

## Source

`request.POST.get("announcement", "")` in `event_announcement_view`, passed through `.strip()` (whitespace trimming only, no HTML neutralization) and then into `build_announcement_html(announcement_text)`.

## Fix

```python
from django.shortcuts import render
from django.utils.html import format_html


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
    return format_html("<div class='announcement'>{0}</div>", announcement_text)
```

## Explanation

`format_html` builds the same wrapper markup as before, but it HTML-escapes every positional/keyword argument before substitution (it is Django's safe equivalent of `str.format` for constructing marked-safe HTML). The `<div class='announcement'>...</div>` structure is treated as trusted static markup, while `announcement_text` is escaped, so characters like `<`, `>`, `"`, and `&` in the organizer's submission are neutralized into text rather than parsed as tags or attributes. Because `format_html` already returns a `SafeString`, the explicit `mark_safe()` call on the manually-concatenated string is removed entirely - that call was the point where the raw, unescaped attacker input was declared trustworthy to the template engine. If richer formatting (e.g. bold/links) is genuinely required in announcements, replace this approach with an allowlist-based HTML sanitizer (e.g. `nh3` or `bleach`, checked for current maintenance status) run over the input before storage/render, rather than reintroducing `mark_safe()` on unsanitized text.
