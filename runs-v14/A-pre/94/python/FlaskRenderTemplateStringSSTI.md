## Verdict

Confirmed. Line 18 uses `render_template_string()` with an f-string that includes unsanitized user input directly in the template. This enables Server-Side Template Injection (SSTI) attacks.

## Source

```python
name = request.args.get("name", "friend")
return render_template_string(f"<h1>Hello {name}!</h1><p>Welcome back.</p>")
```

An attacker can supply template syntax in the `name` parameter, such as `?name={{config}}` or `?name={{request.environ}}`, which Jinja2 will execute, exposing sensitive configuration and environment data.

## Fix

Pass user input through the template context dictionary instead of embedding it in the f-string:

```python
from flask import Flask, request, render_template_string

@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string(
        "<h1>Hello {{ name }}!</h1><p>Welcome back.</p>",
        name=name
    )
```

## Explanation

When variables are passed through `render_template_string()`'s context dictionary (the keyword arguments after the template string), Jinja2 automatically escapes them for HTML context. This prevents template syntax in the user input from being interpreted as code.

The original code embedded the user input directly in an f-string before passing it to `render_template_string()`, which means Jinja2 never sees the raw value—it only sees the already-interpolated string with any template syntax already present and ready for execution.

By moving the interpolation into the Jinja2 template itself using the `{{ name }}` syntax and passing `name` as a context variable, the template engine controls escaping and prevents injection.
