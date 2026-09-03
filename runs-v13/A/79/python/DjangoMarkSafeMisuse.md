## Verdict

**CWE-79 Confirmed**: User-supplied announcement text is embedded directly into HTML markup without escaping, then marked as safe, allowing script injection.

## Source

**File**: `evals/cases/79/python/DjangoMarkSafeMisuse/DjangoMarkSafeMisuse.py`  
**Line**: 23

The vulnerability chain:
- Line 8: `announcement_text` comes from `request.POST` (untrusted user input)
- Line 11: Whitespace is trimmed but no sanitization occurs
- Line 21: The text is embedded into HTML via string formatting without escaping
- Line 23: `mark_safe()` flags the resulting markup as safe, bypassing Django's template autoescaping

An attacker can inject `<script>alert('XSS')</script>` or event handlers like `<img src=x onerror="alert('XSS')">` via the announcement form.

## Fix

Replace lines 20–23 with:

```python
def build_announcement_html(announcement_text):
    from django.utils.html import escape
    escaped_text = escape(announcement_text)
    banner_markup = "<div class='announcement'>{0}</div>".format(escaped_text)
    return mark_safe(banner_markup)
```

**Alternative** (preferred for this pattern): Return the template context variable unescaped and rely on Django template autoescaping in the template:

```python
def build_announcement_html(announcement_text):
    return announcement_text
```

Then in `events/announcement_banner.html`, change `{{ announcement }}` to `{{ announcement }}` (no pipe filter needed; autoescaping is on by default). The `<div>` wrapper can be added in the template instead.

## Explanation

`mark_safe()` tells Django to trust the string and skip autoescaping. This is only safe when you control all content in the string. Here, user input is embedded without escaping first.

The fix applies `escape()` to the user-supplied text before including it in the markup. This converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to entity references, preventing injection. The resulting markup is then safely marked as trusted because it contains no unescaped user input.

The autoescaping approach is cleaner: keep the view simple (just return the text) and let Django templates handle escaping by default, reserving `mark_safe()` for content you genuinely need to render as HTML (like rich-text output from a trusted backend service).
