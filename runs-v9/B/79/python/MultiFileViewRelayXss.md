## Verdict

exploitable

- cwe_id: CWE-79
- location: search_view.py, line 19 (`render_template_string(page_html)`)
- confidence: high

## Source

`request.args.get("q", "")` in `search_controller.search()` (search_controller.py, line 22). This is the Flask query-string parameter `q`, fully attacker-controlled. It is wrapped unmodified into `SearchQuery.term` and passed to `render_results(query)`.

## Fix

Vulnerable code (`search_view.py`):

```python
RESULTS_TEMPLATE_HEADER = "<h1>Search results</h1>"


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    summary_html = "<p>Showing results for: " + query.term + "</p>"
    page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

    # SAST FINDING: CWE-79 reported here. Sink is the next statement.
    return render_template_string(page_html)
```

Fixed code:

```python
RESULTS_TEMPLATE = (
    "<h1>Search results</h1>"
    "<p>Showing results for: {{ term }}</p>"
    "<div id='results'></div>"
)


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    return render_template_string(RESULTS_TEMPLATE, term=query.term)
```

## Explanation

The original code builds the entire HTML document with plain Python string concatenation, splicing `query.term` directly into the markup, and only then hands the finished string to `render_template_string`. Flask's `render_template_string` does enable Jinja2 autoescaping, but autoescaping only encodes values substituted through `{{ }}` placeholders at render time - it has no effect on text that is already baked into the template source before the call, and text merged into the template source this way is also parsed as template syntax, so `term` values could reach further than markup injection into Jinja2 expression evaluation. The fix keeps the template markup as a static string literal and moves `query.term` out of the concatenation into a `{{ term }}` placeholder, passing it as a template context variable (`term=query.term`) instead. Jinja2's autoescaping - on by default for `render_template_string` - now HTML-encodes `term` at render time before it is written into the page, so `<`, `>`, `&`, and quote characters in the search term are neutralized rather than executed, and the term can no longer be interpreted as template syntax.

## Behaviour changes

- The value of `query.term` is now HTML-escaped in the rendered page (e.g. `<` becomes `&lt;`) instead of being emitted raw. This is the security fix itself, not an incidental side effect - legitimate search terms containing `<`, `&`, or quotes will now display their escaped form rather than being interpreted as markup.
- A search term containing Jinja2 template syntax (e.g. `{{ ... }}`) is no longer evaluated as a template expression, since it is passed as data rather than concatenated into the template source. This closes a template-injection path that existed alongside the reported XSS and was not previously flagged.
- No change to the function's return value type, the logging call, the static header/wrapper markup, or the caller (`search_controller.search`), which still receives the same rendered HTML string.
