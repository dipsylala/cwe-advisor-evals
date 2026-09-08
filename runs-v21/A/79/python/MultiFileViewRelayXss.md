## Verdict

CONFIRMED - CWE-79 (Cross-site Scripting) vulnerability exists at line 19 in search_view.py. User-controlled input from the `q` query parameter flows unsanitized into an HTML string that is rendered as a Jinja2 template, allowing script injection.

## Source

The vulnerability originates in search_controller.py at the route handler: `raw_term = request.args.get("q", "")` provides untrusted input from the HTTP request. This raw term is passed to `SearchQuery` and subsequently to `render_results()` in search_view.py, where it is concatenated into an HTML string without escaping.

At line 19 in search_view.py:
```
summary_html = "<p>Showing results for: " + query.term + "</p>"
```

The `query.term` (attacker-controlled) is concatenated directly into the HTML string, and then passed to `render_template_string(page_html)`, which processes it as Jinja2 template content. Although Jinja2 has auto-escaping enabled by default, string concatenation happens before template processing, so the malicious input is treated as template syntax/HTML, not as escaped data.

An attacker can inject a payload like `q=<script>alert(1)</script>` or `q={{ 7*7 }}` which will execute or be evaluated in the template context.

## Fix

### File: search_view.py

```python
"""Renders the search-results page for a given query."""

import logging

from flask import render_template_string

logger = logging.getLogger(__name__)

RESULTS_TEMPLATE_HEADER = "<h1>Search results</h1>"


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    summary_template = "<p>Showing results for: {{ term }}</p>"
    page_html = RESULTS_TEMPLATE_HEADER + summary_template + "<div id='results'></div>"

    return render_template_string(page_html, term=query.term)
```

## Explanation

The fix treats user input as template variable data rather than concatenating it into the template string. By passing `query.term` as a named parameter to `render_template_string()` and referencing it with `{{ term }}` in the template, Jinja2's auto-escaping (enabled by default in Flask) automatically HTML-escapes the value.

This ensures that:
- Malicious HTML tags like `<script>` are escaped to `&lt;script&gt;` and rendered as text
- Template syntax like `{{ }}` and `{% %}` in the input is treated as literal text
- The attacker cannot inject code or break out of the data context

The template string itself remains under developer control; only the user-supplied data is escaped. This is the idiomatic Flask/Jinja2 pattern for safe dynamic content inclusion.
