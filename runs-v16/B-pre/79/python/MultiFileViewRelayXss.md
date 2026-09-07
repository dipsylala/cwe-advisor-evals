## Verdict

Exploitable. The untrusted user input from the URL query parameter `q` flows directly into HTML content without escaping and is rendered via `render_template_string()`, allowing arbitrary HTML and JavaScript injection.

## Source

**File**: search_controller.py  
**Extraction**: `request.args.get("q", "")` in the `search()` function retrieves an attacker-controlled query parameter from the URL. This raw value is wrapped in a `SearchQuery` object and passed to the view layer.

**Data flow**:
1. `raw_term = request.args.get("q", "")` – untrusted URL parameter (no validation)
2. `query = SearchQuery(term=raw_term, ...)` – wraps the untrusted value
3. `query.term` is received by `render_results()` in search_view.py
4. `summary_html = "<p>Showing results for: " + query.term + "</p>"` – concatenates untrusted input into HTML (line 16)
5. `render_template_string(page_html)` – renders the unescaped HTML as a Jinja2 template (line 19, the reported sink)

## Fix

**Vulnerable code** (search_view.py, lines 16–19):
```python
summary_html = "<p>Showing results for: " + query.term + "</p>"
page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
return render_template_string(page_html)
```

**Fixed code**:
```python
import html

RESULTS_TEMPLATE_HEADER = "<h1>Search results</h1>"


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    summary_html = "<p>Showing results for: " + html.escape(query.term) + "</p>"
    page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

    return render_template_string(page_html)
```

## Explanation

The fix applies HTML entity encoding to `query.term` using `html.escape()` from Python's standard library before concatenating it into the HTML string. This converts special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the browser from interpreting them as HTML or JavaScript code. When `render_template_string()` renders the resulting page, any attacker-injected markup or scripts will be displayed as plain text rather than executed. The `html` module is part of Python's standard library (available since 3.2), requiring no additional dependencies.

## Behaviour changes

- **Added import**: `import html` at the module level. This import is from Python's standard library and introduces no external dependencies.
- **Escaping applied**: `query.term` is now wrapped with `html.escape()`, which escapes HTML special characters. This transforms user input like `<img src=x onerror=alert(1)>` into `&lt;img src=x onerror=alert(1)&gt;`, ensuring it is rendered as text content rather than as HTML markup.
- **Return value unchanged**: `render_template_string()` still receives an HTML string as input and still returns a rendered Flask response; the function signature and behaviour remain the same.
- **Template rendering unaffected**: The Jinja2 template rendering (via `render_template_string()`) continues to work normally; the escaping occurs at the string-concatenation level before the template is processed, so template syntax in the fixed string remains intact if needed.
