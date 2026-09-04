## Verdict

Confirmed XSS vulnerability via unescaped user input in HTML template.

## Source

The vulnerability originates in `search_controller.py` at line 22 where `request.args.get("q", "")` retrieves untrusted user input from the query string parameter `q`. This raw user input is passed through a `SearchQuery` object to `search_view.py:render_results()`.

In `search_view.py` at line 16, the untrusted `query.term` is concatenated directly into an HTML string without escaping:

```python
summary_html = "<p>Showing results for: " + query.term + "</p>"
```

At line 19, this unsanitized HTML string is passed to `render_template_string()`, which renders it as part of the response. An attacker can inject arbitrary HTML and JavaScript by providing a malicious query parameter like `?q=<script>alert('XSS')</script>`.

## Fix

Import `escape` from `markupsafe` at the top of `search_view.py`:

```python
from markupsafe import escape
```

Then escape the user-controlled `query.term` when building the HTML:

```python
summary_html = "<p>Showing results for: " + escape(query.term) + "</p>"
```

## Explanation

The `escape()` function converts HTML special characters (`<`, `>`, `&`, `"`, `'`) into their safe HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that any user-supplied input is treated as text content rather than HTML markup, preventing the browser from interpreting injected scripts or tags.

This is the standard XSS prevention mechanism for Flask applications and is built into the framework's templating system. By escaping the user input before inserting it into the template, the application neutralizes the XSS vector while preserving the legitimate search term display functionality.
