## Verdict

The code at line 18 is vulnerable to template injection via `render_template_string()`. User input from the `name` query parameter is interpolated directly into the template string via an f-string, allowing an attacker to inject Jinja2 template expressions.

## Source

The `name` parameter originates from `request.args.get("name", "friend")` at line 15, which is untrusted user input. This value is concatenated into a template string using an f-string at line 18 and passed to `render_template_string()`, which interprets Jinja2 syntax in the entire string.

## Fix

### File: greeting.py

```python
"""Personalized greeting page for the marketing site.

Builds a short welcome banner from a query-string name so campaign links
like /greet?name=Alex render "Hello Alex!" without a static template file
per campaign.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    template = "<h1>Hello {{ name }}!</h1><p>Welcome back.</p>"
    return render_template_string(template, name=name)


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix moves the user-controlled `name` value out of the template string and into the context variables passed to `render_template_string()`. 

The vulnerable code used an f-string to interpolate `name` directly into the template: `f"<h1>Hello {name}!</h1><p>Welcome back.</p>"`. This allowed the entire template to be constructed from user input, enabling Jinja2 expressions injected via the `name` parameter.

The fixed code separates the template structure from the data:
- The template string contains only literal HTML and a Jinja2 variable placeholder: `"<h1>Hello {{ name }}!</h1><p>Welcome back.</p>"`
- The user input is passed as a context variable: `render_template_string(template, name=name)`

When Flask renders this template, Jinja2 will safely escape or handle the `name` variable value, preventing template injection. An attacker can no longer inject template syntax through the `name` parameter because it is treated as data, not as part of the template definition.
