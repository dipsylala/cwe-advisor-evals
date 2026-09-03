## Verdict

CONFIRMED - Cross-site scripting vulnerability via unescaped user input in HTML rendering.

## Source

Untrusted user input originates from `request.args.get("q", "")` in `search_controller.py` line 22. The query parameter is wrapped in a `SearchQuery` object and passed to `render_results()` as `query.term`.

## Fix

Import `html` and use `html.escape()` to encode the user-supplied term before concatenating it into the HTML string:

```python
"""Renders the search-results page for a given query."""

import html
import logging

from flask import render_template_string

logger = logging.getLogger(__name__)

RESULTS_TEMPLATE_HEADER = "<h1>Search results</h1>"


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    escaped_term = html.escape(query.term)
    summary_html = "<p>Showing results for: " + escaped_term + "</p>"
    page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

    # User input is now HTML-encoded and safe from XSS
    return render_template_string(page_html)
```

## Explanation

The vulnerability occurs because `query.term` (attacker-controlled user input) is concatenated directly into an HTML string without encoding. When passed to `render_template_string()`, malicious HTML or script tags in the query parameter will be rendered and executed in the browser.

`html.escape()` converts special HTML characters to entity references: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and `"` becomes `&#x22;`. This ensures the user input is treated as text data, not as executable HTML or script code. The escaping is applied before the string is built, so the template engine receives a safe HTML string where all user content is neutralized.

## Behaviour changes

- User-supplied search terms containing HTML special characters (e.g., `<`, `>`, `&`, `"`) will be displayed as escaped entities in the rendered page. For example, a search for `<script>` will display `&lt;script&gt;` in the output, not a script tag.
- Legitimate search queries without special characters will render unchanged.
- No change to the page structure, logging, or template rendering mechanism.
