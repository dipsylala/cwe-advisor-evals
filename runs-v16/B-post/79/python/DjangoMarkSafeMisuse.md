## Verdict

Exploitable. Untrusted user input from `request.POST` is concatenated directly into HTML markup, then passed through `mark_safe()` which disables Django's template auto-escaping, allowing arbitrary script injection.

## Source

**Source**: `request.POST.get("announcement", "")` at line 8 (organizer-submitted announcement text)

**Sink**: `mark_safe(banner_markup)` at line 23

**Data flow**: User input → strip() (no sanitization) → string .format() into HTML → mark_safe() disables escaping → returned to template context

An attacker can submit `announcement=<img src=x onerror=alert(1)>` and the rendered HTML will execute the injected script.

## Fix

**Vulnerable code** (lines 20–23):
```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return mark_safe(banner_markup)
```

**Fixed code**:
```python
def build_announcement_html(announcement_text):
    banner_markup = "<div class='announcement'>{0}</div>".format(announcement_text)
    return banner_markup
```

**Changes**: Remove the `mark_safe()` call entirely. Return the string without marking it safe.

**Explanation**: `mark_safe()` explicitly disables Django's template auto-escaping for the returned value. Removing it allows Django's default template escaping to encode HTML entities in the user-controlled `announcement_text` — converting `<` to `&lt;`, `>` to `&gt;`, quotes to `&quot;`, preventing script injection. When the template renders `{{ announcement }}`, Django's auto-escaping (enabled by default in all Django projects) will encode the string, ensuring `<img onerror=...>` is displayed as plain text, not executed.

## Behaviour changes

None. The function still returns a string containing the announcement wrapped in a div. The only change is that HTML special characters in the user input are now entity-encoded instead of rendered as raw markup. Legitimate content containing `<`, `>`, `&`, or quotes will display correctly as escaped text rather than interpreted as HTML — this is the intended behaviour for untrusted user input.

- **Original behaviour**: `<img src=x onerror=alert(1)>` renders as executable HTML script tag.
- **Fixed behaviour**: `<img src=x onerror=alert(1)>` renders as the literal text `&lt;img src=x onerror=alert(1)&gt;` in the browser.

This preserves the function's contract (returns a string suitable for template rendering) while closing the XSS vector.
