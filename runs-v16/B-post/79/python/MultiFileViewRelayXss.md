## Verdict
exploitable

## Source
Untrusted user input from HTTP query parameter `q` obtained via `request.args.get("q", "")` in `search_controller.py` line 22, stored in `query.term`.

## Fix

**Vulnerable code:**
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
RESULTS_TEMPLATE = RESULTS_TEMPLATE_HEADER + "<p>Showing results for: {{ term }}</p><div id='results'></div>"

def render_results(query):
    logger.info("Rendering search results, requested_at=%s", query.requested_at)

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return render_template_string(RESULTS_TEMPLATE, term=query.term)
```

## Explanation
The vulnerability occurs because untrusted input (`query.term`) is concatenated directly into the template source string before being passed to `render_template_string()`. This causes the input to be compiled and evaluated as Jinja2 template code, allowing attackers to inject expressions like `{{ 7*7 }}` or access template globals like `{{ config }}`. The fix restructures the code to keep the template source constant with a placeholder variable (`{{ term }}`), and passes the untrusted input as a keyword argument instead. Jinja2's built-in autoescaping then safely encodes the value as text rather than template code, preventing template expression execution.

## Behaviour changes
The template is now defined as a module-level constant (`RESULTS_TEMPLATE`) rather than built dynamically on each call. This is a performance improvement with no functional change: the same HTML output is produced for identical inputs, and the template source is now immutable and safely separated from untrusted data.
