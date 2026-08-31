## Verdict

Confirmed. `build_announcement_html` interpolates the raw, attacker-controlled `announcement_text` (from `request.POST`) directly into an HTML string via `str.format`, then wraps the result in `mark_safe`. `mark_safe` does not sanitize anything - it only tells Django's template engine to skip autoescaping for that string. Any HTML/JS the organizer submits in the `announcement` field is rendered verbatim in `events/announcement_banner.html`, giving stored XSS.

## Source

`request.POST.get("announcement", "")` in `event_announcement_view`, passed (after only a `.strip()`, which does not remove markup) into `build_announcement_html`.

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

`format_html` builds the same wrapped markup but HTML-escapes every positional/keyword argument before substitution, then returns a `SafeString` - it replaces both the manual `"...".format(...)` call and the explicit `mark_safe` in one step, so there is no longer any point where unescaped user input reaches the "trusted" pool of markup. The static `<div class='announcement'>...</div>` skeleton is still trusted (it comes from the source code, not the request), while `announcement_text` is now always escaped regardless of what the organizer submits - `<script>`, `onerror=`, quotes, etc. render as inert text inside the div rather than executing. Because the class attribute is fixed and only the trailing text is untrusted, `format_html` is a drop-in that needs no other change to the view or template.

If the banner is ever meant to support a restricted subset of real HTML (e.g. bold or links) rather than plain text, replace this with a maintained HTML-sanitizing library (e.g. `nh3`) run over `announcement_text` before any `mark_safe`/`format_html` use, rather than hand-rolling an allowlist.
