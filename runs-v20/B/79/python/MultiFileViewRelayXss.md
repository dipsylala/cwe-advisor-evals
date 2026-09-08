## Verdict

Exploitable. CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting), confidence: high.

## Source

`request.args.get("q", "")` in `search_controller.py` (line 22) - the `q` query-string parameter is fully attacker-controlled. It is wrapped, unmodified, into `SearchQuery.term` (line 23) and passed to `render_results(query)`.

## Fix

### File: search_view.py

```python
"""Renders the search-results page for a given query."""

import logging

from flask import render_template_string

logger = logging.getLogger(__name__)

RESULTS_TEMPLATE_HEADER = "<h1>Search results</h1>"
RESULTS_TEMPLATE = (
    RESULTS_TEMPLATE_HEADER
    + "<p>Showing results for: {{ term }}</p>"
    + "<div id='results'></div>"
)


def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    return render_template_string(RESULTS_TEMPLATE, term=query.term)
```

## Explanation

`query.term` reached `render_template_string()` by being string-concatenated straight into the template *source* (`summary_html = "<p>Showing results for: " + query.term + "</p>"`). At that sink, escaping the value would not have closed the finding: `render_template_string()` compiles its argument as a Jinja2 template, so any Jinja delimiters in the attacker-controlled term (`{{ ... }}`, `{% ... %}`) are parsed and executed regardless of HTML-escaping applied to the string first - this is server-side template injection layered on top of the XSS, not merely encoding on the wrong output. The fix keeps the template source a compile-time constant (`RESULTS_TEMPLATE`) containing only a `{{ term }}` placeholder, and passes the untrusted value as a keyword argument through Jinja2's rendering context instead of interpolating it into the source string. `render_template_string()` has Jinja2 autoescaping enabled by default in Flask, so the context variable is HTML-escaped on output, and because it is data bound to a template variable - not text spliced into the template source - it can no longer be parsed as template syntax. This closes both the reflected-XSS path and the template-injection path in a single change, per `cwe/79/python/INDEX.md`'s guidance for this exact sink shape.

## Behaviour changes

- The literal HTML string built by concatenation (`summary_html`, `page_html`) is replaced by a module-level constant template string plus a Jinja2 context argument. The rendered output for ordinary input is byte-for-byte equivalent to before (verified below) except that HTML-significant characters in `term` (`<`, `>`, `&`, `"`, `'`) are now entity-escaped in the response instead of passed through raw - this is the intended effect of closing the weakness, not an unrelated change.
- No change to the function signature, the `logger.info()` call, the header constant's value, the `<div id='results'></div>` fragment, or the caller (`search_controller.py`, not modified).
- No arguments to `render_template_string()` were left implicit or altered beyond adding the `term=` keyword needed to bind the placeholder; return value and failure behaviour (a `TemplateSyntaxError` would only be raised by a malformed constant template, which is fixed at deploy time, not by user input) are unchanged.

Otherwise: none.

## Verification

Ran the fixed file through `python -m py_compile` (clean, exit 0) in a scratch copy outside the repo. Also executed it against the real Flask/Jinja2 runtime (Flask 3.1.3) inside an app context with three inputs: `<script>alert(1)</script>` rendered as `&lt;script&gt;alert(1)&lt;/script&gt;` (no raw markup in the response); `{{ 7*191 }}` (an SSTI probe that the original concatenation sink would have evaluated to `1337`) rendered back as the literal text `{{ 7*191 }}`, confirming the template-injection path is also closed; and `cats & dogs "quoted"` rendered as `cats &amp; dogs &#34;quoted&#34;`, confirming legitimate content is preserved, just correctly escaped.
