## Verdict

Real XSS vulnerability. The search query term flows unescaped from user input through to rendered HTML.

## Source

**Call chain:**
1. `search_controller.py` line 22: `raw_term = request.args.get("q", "")` — untrusted user input
2. `search_controller.py` line 23: Wraps it in `SearchQuery(term=raw_term, ...)`
3. `search_view.py` line 15: `"<p>Showing results for: " + query.term + "</p>"` — concatenates unsanitized input into HTML
4. `search_view.py` line 19: `render_template_string(page_html)` — renders the HTML with embedded user input

The vulnerability is on line 19 of `search_view.py`, where `render_template_string()` renders HTML containing the unescaped `query.term`.

## Fix

```python
"""Renders the search-results page for a given query."""

import logging

from flask import render_template_string
from markupsafe import escape

logger = logging.getLogger(__name__)

RESULTS_TEMPLATE_HEADER = "<h1>Search results</h1>"


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    summary_html = "<p>Showing results for: " + escape(query.term) + "</p>"
    page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

    return render_template_string(page_html)
```

**Key changes:**
- Import `escape` from `markupsafe` (line 6)
- Wrap `query.term` with `escape()` on line 15

## Explanation

The vulnerability occurs because user-controlled input (`query.term`) is concatenated directly into an HTML string and then passed to `render_template_string()`. An attacker can inject arbitrary HTML and JavaScript by including payloads like `<script>alert('XSS')</script>` in the search query parameter.

The fix uses Flask's `escape()` function from `markupsafe`, which is the standard HTML escaping utility in Flask. It converts HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the injected input from being interpreted as HTML or JavaScript.

This is a primary defense: it neutralizes the malicious input at the point where it enters the HTML output, ensuring that any special characters are treated as literal text rather than markup.
