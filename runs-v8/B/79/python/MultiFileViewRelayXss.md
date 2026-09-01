## Verdict

Exploitable.

## Source

search_controller.py line 22: User-supplied query parameter `q` is obtained via `request.args.get("q", "")` with no constraints. This untrusted value is wrapped in a SearchQuery object and passed to the view layer without validation or encoding.

## Fix

**Vulnerable code (search_view.py, lines 12-19):**
```python
def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    summary_html = "<p>Showing results for: " + query.term + "</p>"
    page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return render_template_string(page_html)
```

**Fixed code:**
```python
import html
import logging

from flask import render_template_string

logger = logging.getLogger(__name__)

RESULTS_TEMPLATE_HEADER = "<h1>Search results</h1>"


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    summary_html = "<p>Showing results for: " + html.escape(query.term) + "</p>"
    page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

    return render_template_string(page_html)
```

## Explanation

The vulnerability exists because user-supplied query text is concatenated directly into an HTML string without escaping, and then passed to `render_template_string()`. An attacker can inject script tags or event handlers via the query parameter. The fix applies HTML entity encoding to the untrusted `query.term` using Python's built-in `html.escape()` before concatenating it into the HTML string. This converts characters like `<`, `>`, `&`, and quotes into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, etc.), ensuring they render as literal text rather than executable markup. The `html` module is part of Python's standard library and requires no external dependencies.

## Behaviour changes

None. The sink `render_template_string()` receives the same HTML structure with identical semantics - legitimate content containing special characters (e.g. mathematical notation or user-generated text with `<` or `&`) renders correctly as display text rather than markup. The return value and all side effects remain unchanged.
