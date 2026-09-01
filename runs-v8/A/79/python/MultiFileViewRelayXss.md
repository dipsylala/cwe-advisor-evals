## Verdict
Confirmed. Reflected XSS vulnerability. Untrusted query parameter flows through `SearchQuery.term` into HTML string concatenation at line 15 of search_view.py, then rendered unsafely at line 19.

## Source
search_controller.py, line 22: `raw_term = request.args.get("q", "")` — retrieves untrusted input from the HTTP query string parameter `q`.

## Fix
Escape the untrusted input using Flask/Jinja2's built-in escaping before concatenating into the HTML string. Replace line 15 in search_view.py:

**Before:**
```python
summary_html = "<p>Showing results for: " + query.term + "</p>"
```

**After:**
```python
from markupsafe import escape

summary_html = "<p>Showing results for: " + escape(query.term) + "</p>"
```

Alternatively, use Jinja2 template syntax with automatic escaping enabled (the default in Flask):

**After (template approach):**
```python
from flask import render_template_string

def render_results(query):
    summary_html = render_template_string("<p>Showing results for: {{ term }}</p>", term=query.term)
    page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"
    return render_template_string(page_html)
```

The first approach (explicit `escape()`) is simpler here since only one value needs escaping. The second approach uses Jinja2's automatic escaping, which is safer for complex templates.

## Explanation
The vulnerability occurs because `query.term` contains untrusted user input from the `q` query parameter. This input is concatenated directly into an HTML string using Python string concatenation, which performs no escaping. When `render_template_string()` renders this string, any JavaScript injected in the `q` parameter (e.g., `?q=<script>alert(1)</script>`) will be executed in the browser.

The fix escapes HTML metacharacters (`<`, `>`, `&`, `"`, `'`) in the user input before including it in the HTML. This converts the malicious payload into harmless text. For example, `<script>` becomes `&lt;script&gt;`, which renders as literal text rather than executing as an HTML tag.

Using Jinja2's template variables with automatic escaping (the default) provides defense-in-depth by automatically escaping any expression output unless explicitly marked safe with the `|safe` filter.
