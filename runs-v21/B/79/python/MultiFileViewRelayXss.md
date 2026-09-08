## Verdict

Exploitable. Untrusted user input from the query parameter flows through string concatenation into the template source of `render_template_string()`, allowing attackers to inject Jinja2 template syntax or HTML/JavaScript that executes in the victim's browser.

## Source

**Source**: Line 22 in search_controller.py
```python
raw_term = request.args.get("q", "")
```

The query parameter `q` is untrusted user input. This flows to `SearchQuery.term`, then into string concatenation at search_view.py line 15, and finally into the template source passed to `render_template_string()` at line 19.

**Sink**: Line 19 in search_view.py
```python
return render_template_string(page_html)
```

The entire `page_html` string, including the concatenated user input, is compiled and rendered as a Jinja2 template. An attacker can inject template directives like `{{ 7*191 }}` or HTML/JavaScript that the template interprets and renders.

## Fix

### File: search_view.py

```python
"""Renders the search-results page for a given query."""

import logging

from flask import render_template_string

logger = logging.getLogger(__name__)

RESULTS_TEMPLATE = "<h1>Search results</h1><p>Showing results for: {{ term }}</p><div id='results'></div>"


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)
    return render_template_string(RESULTS_TEMPLATE, term=query.term)
```

## Explanation

The fix restructures the code to keep the template source constant and passes the untrusted user input through Jinja2's context dictionary instead of concatenating it into the template source. The template now uses `{{ term }}` as a placeholder variable. When `render_template_string()` renders the template, Jinja2 automatically HTML-escapes the value of the `term` variable (encoding `<` as `&lt;`, `>` as `&gt;`, etc.), preventing the injection of both template directives and HTML/JavaScript. The root cause—concatenating user input into the template source string—is eliminated, and the value arrives at the renderer as data, not code.

## Behaviour changes

1. **Template constant extracted**: A new module-level constant `RESULTS_TEMPLATE` was created to hold the fixed template HTML instead of concatenating it inside the function. This prevents runtime string assembly that could be influenced by user input.

2. **render_template_string() call changed**: The call now passes two arguments instead of one—the constant template source and a keyword argument `term=query.term`—instead of the original single concatenated string. This is a change in how arguments are supplied, not a change in the function's behavior or return value; Jinja2's rendering engine still produces the same HTML output for legitimate input.

3. **Removed intermediate variables**: The `summary_html` and `page_html` intermediate variables were removed because the fix consolidates the template into a single constant, eliminating the string concatenation steps. This simplifies the code and makes the data flow clearer.

4. **Auto-escaping enforcement**: The fix now explicitly relies on Jinja2's default auto-escaping behavior (enabled in Flask for template strings), whereas the original code concatenated raw strings and passed them to the template engine without variable-level escaping. Legitimate output that contains `<`, `&`, or quotes is now HTML-encoded in the output, which is the correct behavior for text content in HTML.
