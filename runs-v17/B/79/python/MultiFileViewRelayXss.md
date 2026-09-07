## Verdict

Exploitable. Untrusted user input from the URL query parameter is concatenated into a template string and passed to `render_template_string()` without escaping, allowing arbitrary template expressions to execute.

## Source

**File**: search_controller.py  
**Location**: Line 22 - `raw_term = request.args.get("q", "")`

The untrusted query parameter `q` is extracted from the user's HTTP request and wrapped into a `SearchQuery` object, then passed to the `render_results()` function.

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

    template_html = RESULTS_TEMPLATE_HEADER + "<p>Showing results for: {{ term }}</p><div id='results'></div>"
    
    return render_template_string(template_html, term=query.term)
```

## Explanation

The vulnerability was introduced by concatenating the untrusted `query.term` directly into the HTML string on line 15, then passing that string to `render_template_string()`. This means the template source itself contains user input, and Jinja2 compiles and evaluates that input as template code, allowing payloads like `{{ 7*191 }}` or `{{ __import__('os').system('...') }}` to execute.

The fix restructures the template to keep the source constant while passing user input as a context variable. Line 15 now builds a template string with a `{{ term }}` placeholder, and line 18 passes the untrusted value as `term=query.term` to `render_template_string()`. Flask's `render_template_string()` has autoescaping enabled by default, so Jinja2 will automatically escape the value when rendering `{{ term }}`, converting special characters like `<`, `>`, and `&` to their HTML entity equivalents. This prevents the user input from being interpreted as template syntax or HTML tags.

## Behaviour changes

The fix changes the control flow from string concatenation into template rendering context. The functional output to the client remains the same—an HTML page with the search term displayed in a paragraph—but the user input now flows through Jinja2's autoescaping layer, which escapes HTML-special characters. No implicit parameters were changed, no return value was altered, and the sink contract is preserved: `render_template_string()` still receives a template string and returns rendered HTML.
