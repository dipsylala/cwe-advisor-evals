## Verdict

Exploitable. Untrusted user input from an HTTP query parameter is directly concatenated into an HTML string and rendered without encoding, allowing arbitrary JavaScript execution.

## Source

`request.args.get("q", "")` in search_controller.py (line 22), passed to `SearchQuery` as the `term` attribute, which originates from user-supplied HTTP request data and is never validated or encoded before being rendered.

## Fix

**Vulnerable code (search_view.py, lines 15-19):**
```python
summary_html = "<p>Showing results for: " + query.term + "</p>"
page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

# SAST FINDING: CWE-79 reported here
return render_template_string(page_html)
```

**Fixed code:**
```python
from html import escape

summary_html = "<p>Showing results for: " + escape(query.term) + "</p>"
page_html = RESULTS_TEMPLATE_HEADER + summary_html + "<div id='results'></div>"

return render_template_string(page_html)
```

## Explanation

The fix applies context-aware HTML encoding to the untrusted `query.term` value using `html.escape()` before concatenating it into the HTML string. This neutralizes any HTML metacharacters in the user input, preventing them from being interpreted as markup or script code when the string is rendered. Since `render_template_string()` does not automatically escape HTML already present in the input string (it only escapes template variables), the encoding must be applied at the point where untrusted data enters the HTML—in this case, the string concatenation.

## Behaviour changes

None. For legitimate input, `html.escape()` is a no-op (passes alphanumeric and common safe characters through unchanged). For input containing HTML metacharacters, those characters are converted to named entities (e.g., `<` becomes `&lt;`), which display correctly in the browser as literal text rather than being interpreted as markup.
