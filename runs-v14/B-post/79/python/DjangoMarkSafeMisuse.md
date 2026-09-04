## Verdict
Exploitable. Cross-site scripting vulnerability via untrusted user input marked as safe without sanitization.

## Source
`announcement_text` parameter sourced from untrusted user input via `request.POST.get("announcement", "")` at line 8, passed through `build_announcement_html()` without validation or encoding.

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
from html import escape

def build_announcement_html(announcement_text):
    # Escape user input to prevent XSS injection
    escaped_text = escape(announcement_text)
    banner_markup = "<div class='announcement'>{0}</div>".format(escaped_text)
    return mark_safe(banner_markup)
```

## Explanation
The vulnerability exists because untrusted user input from `request.POST` is directly embedded into HTML markup via string formatting without any escaping, then `mark_safe()` is applied. This combination allows an attacker to inject arbitrary HTML and JavaScript. The fix applies `html.escape()` to the user input before embedding it in the markup, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents. This ensures the user input is treated as data, not executable code. The `mark_safe()` call then legitimately protects the hardcoded HTML structure while the escaped user content remains safe within it.

## Behaviour changes
The function now imports `html.escape` (adds a single import statement at the module level). The function returns HTML with user-supplied characters converted to entity references (e.g., `<script>` becomes `&lt;script&gt;`), which renders as plain text in the browser rather than executing as code. Legitimate content containing special characters (e.g., markup-free user text with `<`, `&`, or quotes) is preserved and displays correctly but cannot be interpreted as HTML markup.
