## Verdict

**CONFIRMED** — Code injection via Jinja2 template rendering of untrusted input.

## Source

Line 18 in `greeting.py`:
```python
return render_template_string(f"<h1>Hello {name}!</h1><p>Welcome back.</p>")
```

The `name` variable originates from `request.args.get("name", "friend")` on line 15, which is untrusted HTTP query-string input. Passing it to `render_template_string()` allows an attacker to inject Jinja2 template syntax (e.g., `{{ 7*7 }}`, `{{ request.environ }}`) which will be evaluated by the Jinja2 template engine, executing arbitrary Python code within the application context.

## Fix

Replace `render_template_string()` with safe HTML construction using `escape()` to neutralize template syntax:

```python
from flask import Flask, request, escape

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return f"<h1>Hello {escape(name)}!</h1><p>Welcome back.</p>"

if __name__ == "__main__":
    app.run()
```

## Explanation

The vulnerability exists because `render_template_string()` compiles and evaluates the template string as Jinja2 source code. Jinja2 template expressions (delimited by `{{ }}`, `{% %}`, etc.) are evaluated at runtime, not escaped as literal text. An attacker sending `?name={{request.environ}}` injects a request object reference that executes during template rendering.

The fix removes `render_template_string()` entirely, which is unnecessary here since the template structure (the greeting banner HTML) is static and only the `name` value varies. Instead, use safe string concatenation with `escape()`, which HTML-encodes the user-supplied name so that any template syntax, script tags, or special characters are rendered as literal text in the output. The `escape()` function (from `markupsafe`, included with Flask) converts characters like `<`, `>`, `&`, `"`, and `'` to their HTML entity equivalents, preventing both HTML injection and Jinja2 template injection.

For cases where dynamic templates genuinely cannot be avoided, the knowledge base recommends `jinja2.sandbox.SandboxedEnvironment` — but that applies only when template *source* must come from the user. Here, the template is static and only data varies, so escaping data is the correct pattern.

## Behaviour changes

- Before: Jinja2 template expressions in the `name` parameter are evaluated as Python code.
- After: Jinja2 template expressions in the `name` parameter are rendered as literal HTML text, safely displayed in the response.
- Request `GET /greet?name={{7*7}}` previously computed the expression and rendered it; now it outputs the literal text `{{7*7}}` within the heading, harmless.
- Performance: Slight improvement; no template compilation or rendering overhead per request.
