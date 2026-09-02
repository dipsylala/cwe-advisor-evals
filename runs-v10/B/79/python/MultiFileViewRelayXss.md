## Verdict

The finding is **confirmed**. The vulnerability is a reflected XSS: untrusted user input from the query parameter is concatenated into HTML without escaping and then rendered via `render_template_string()`.

## Source

User-controlled input enters via `request.args.get("q", "")` in search_controller.py and is passed to `SearchQuery.term` without validation or encoding. This untrusted data flows into search_view.py.

## Fix

Apply HTML escaping to `query.term` before concatenating it into the HTML string. Import `html` and use `html.escape()`:

```python
"""Renders the search-results page for a given query."""

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

The vulnerability exists because `query.term` contains raw user input (the `q` parameter from the URL). When concatenated into an HTML string and passed to `render_template_string()`, any special characters or script tags in the input are rendered as-is without escaping, allowing an attacker to inject `<script>`, event handlers, or other HTML constructs.

The fix applies `html.escape()` to convert HTML special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, etc.). This prevents the browser from interpreting injected HTML or JavaScript as code—the input remains data, not executable markup.

`html.escape()` is a standard library function and is the correct choice for this context because the data is being rendered into an HTML body element where entity encoding is appropriate.

## Behaviour changes

- User input containing `<`, `>`, `&`, quotes, or other special characters that previously would have been rendered as HTML markup is now rendered as literal text (escaped).
- A search query like `q=<script>alert(1)</script>` now displays literally in the page instead of executing JavaScript.
- Legitimate search queries with ampersands, angle brackets, or quotes (e.g., `q=Cats & Dogs`, `q=2<3`) now render correctly as text instead of being interpreted as HTML.
