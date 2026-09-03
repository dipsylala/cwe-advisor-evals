## Verdict

Exploitable. Untrusted user input from `request.POST` flows directly into HTML markup that is then marked safe, disabling Django's auto-escaping and allowing arbitrary script injection.

## Source

`request.POST.get("announcement", "")` on line 8 of DjangoMarkSafeMisuse.py. The POST parameter is user-controlled and untrusted.

## Fix

**Vulnerable code (line 20-23):**

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
    banner_markup = "<div class='announcement'>{0}</div>".format(html.escape(announcement_text))
    return banner_markup
```

## Explanation

The fix uses `html.escape()` to encode special characters in the untrusted input before embedding it into the HTML string. This converts `<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`, and `"` to `&quot;`, rendering them as literal text in the browser rather than executable markup. Removing the `mark_safe()` call allows Django's template auto-escaping (enabled by default) to provide defence-in-depth on the returned value. Together these changes prevent injection of scripts or HTML while allowing legitimate content containing special characters to render correctly.

## Behaviour changes

- The import of `html` module is added; this is part of Python's standard library with no external dependency or version tracking required.
- Special characters in the announcement text are now HTML-entity encoded in the output. For example, `<script>` will appear as `&lt;script&gt;` in the rendered HTML. This is the intended defence: legitimate text containing `<`, `>`, `&`, or `"` will display those characters without breaking the page, and malicious payloads will be neutralized.
- The function no longer bypasses Django's template escaping. When the returned markup is rendered in the template context, it will be treated as regular data and escaped appropriately by the template engine's auto-escaping (which is enabled by default in Django).
