## Verdict

Real issue. The code passes unsanitized user input directly into `render_template_string()` via f-string interpolation, allowing an attacker to inject Jinja2 template syntax and execute arbitrary code.

## Source

File: greeting.py, line 18
```python
return render_template_string(f"<h1>Hello {name}!</h1><p>Welcome back.</p>")
```

The `name` variable comes from `request.args.get("name", "friend")` (line 15), which is attacker-controlled. Using f-string interpolation to embed it directly into the template string passes it to Jinja2's template engine, which interprets any template syntax it contains. An attacker can inject `{{ 7*7 }}`, `{{ config }}`, or similar to execute code.

## Fix

### File: greeting.py

```python
"""Personalized greeting page for the marketing site.

Builds a short welcome banner from a query-string name so campaign links
like /greet?name=Alex render "Hello Alex!" without a static template file
per campaign.
"""

from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    return render_template_string("<h1>Hello {{ name }}!</h1><p>Welcome back.</p>", name=escape(name))


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix removes f-string interpolation and uses Jinja2's template variable syntax instead:

1. Change the template string from `f"<h1>Hello {name}!</h1>..."` to `"<h1>Hello {{ name }}!</h1>..."` to use Jinja2 variable placeholder syntax.
2. Pass the `name` variable as a context parameter to `render_template_string()`.
3. Wrap the name with `escape()` from `markupsafe` to ensure any HTML special characters and template syntax are neutralized before template rendering.

This approach prevents template injection: the name is now treated as data to be rendered, not as template code to be evaluated. Any `{{ }}` or `{%` sequences in the user input will be escaped and displayed literally.

