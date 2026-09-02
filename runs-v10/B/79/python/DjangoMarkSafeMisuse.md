## Verdict

Real vulnerability. `mark_safe()` disables Django's HTML auto-escaping on a string built from untrusted user input (`request.POST.get("announcement")`), allowing an attacker to inject arbitrary HTML and JavaScript.

## Source

`request.POST.get("announcement", "")` at line 8 - attacker-controlled form data, passed through `strip()` (which does not escape), interpolated into an HTML string at line 21, and marked as safe at line 23.

## Fix

Remove the `mark_safe()` call and return the plain string. Django's template auto-escaping will safely encode HTML entities when the value is rendered in the template.

**Before (line 20-23):**
```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return mark_safe(banner_markup)
```

**After (line 20-23):**
```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    return banner_markup
```

## Explanation

The `mark_safe()` function explicitly disables Django's auto-escaping protection for that value. When the template renders `{{ announcement }}`, Django's default behavior is to escape HTML metacharacters (`<` → `&lt;`, etc.), which neutralizes XSS payloads. By removing `mark_safe()`, the raw HTML string is returned to the template context, where the template engine's auto-escaping (enabled by default in Django) will safely encode any HTML tags in the user input before rendering. This preserves the wrapper `<div>` structure while protecting against injection of `<script>`, `<img onerror=>`, and other attack vectors.

## Behaviour changes

User-supplied content containing `<`, `>`, `&`, or quotes will be displayed as HTML entities (e.g., `<script>` displays as `&lt;script&gt;`) rather than rendered as tags. This is the intended behaviour—user input should never be interpreted as HTML markup. Any legitimate use case requiring rich HTML content (links, formatting, etc.) should use a sanitization library like `nh3.clean()` with a strict allowlist of permitted tags and attributes, applied to the user input before constructing the HTML string.
