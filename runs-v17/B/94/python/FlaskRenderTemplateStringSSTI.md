## Verdict

The vulnerability is confirmed. Line 18 passes untrusted user input directly into a Jinja2 template source string, enabling template injection attacks.

## Source

- **Variable**: `name` (from `request.args.get("name", "friend")`)
- **Sink**: `render_template_string()` on line 18
- **Data Flow**: Query parameter → request handler → f-string template → `render_template_string()` compilation

An attacker can supply `?name={{7*7}}` to execute Jinja2 expressions, or `?name={{__import__('os').system('id')}}` to run arbitrary Python code.

## Fix

The vulnerability is remediated by using a static template and passing the untrusted value as a context variable, which Jinja2 auto-escapes by default.

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

    return render_template_string("<h1>Hello {{ name }}!</h1><p>Welcome back.</p>", name=name)


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix separates the static template structure from the dynamic user data. Instead of interpolating `name` directly into the template string via f-string, the template is kept static and `name` is passed as a context variable through the `name=name` keyword argument. Jinja2's auto-escaping (enabled by default in Flask) will HTML-escape any special characters in the value, preventing both HTML injection and template injection. An attacker passing `?name={{7*7}}` will now receive the literal string `<h1>Hello {{7*7}}!</h1>...</h1>` as output, not the evaluated result.

## Behaviour changes

Normal (safe) inputs produce identical output: `?name=Alex` renders the same welcome page before and after the fix. Malicious inputs that previously executed template code are now treated as literal text and safely displayed. No functionality is lost; the application still renders personalized greetings from the query parameter, but now safely.
