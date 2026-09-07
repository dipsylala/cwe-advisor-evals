## Verdict
CONFIRMED: CWE-79 (Cross-site Scripting)

## Source
User-supplied search query (`query.term`) is concatenated directly into HTML without escaping, then passed to `render_template_string()`. An attacker can inject malicious HTML or Jinja2 template syntax through the search parameter.

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

    template = RESULTS_TEMPLATE_HEADER + "<p>Showing results for: {{ query_term }}</p>" + "<div id='results'></div>"

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return render_template_string(template, query_term=query.term)
```

## Explanation
The vulnerability stems from concatenating unsanitized user input (`query.term`) directly into HTML that is then rendered as a Jinja2 template. This allows attackers to inject XSS payloads or malicious Jinja2 template expressions.

The fix separates data from template by using Jinja2's template variable syntax `{{ query_term }}` instead of string concatenation. When variables are rendered via `{{ }}` in Jinja2, they are automatically HTML-escaped by default in Flask. This prevents both HTML injection (e.g., `<img onerror=...>`) and Jinja2 template injection attacks.

The fix:
1. Moves user input out of the template string
2. Passes it as a context variable to `render_template_string()`
3. Uses Jinja2's built-in escaping (default behavior for `{{ }}` syntax) to neutralize malicious content
