## Verdict

Exploitable. The untrusted `name` parameter from `request.args.get()` is interpolated into an f-string that becomes the template source passed to `render_template_string()`. An attacker can inject Jinja2 template syntax (e.g., `?name={{config.secret_key}}`) to execute template code and access Flask internals.

## Source

HTTP query parameter `name` via `request.args.get("name", "friend")` at line 15, flows untrusted to line 18.

## Fix

Replace the f-string template interpolation with a literal template string and pass the untrusted input as a context variable:

```python
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string(
        "<h1>Hello {{ name }}!</h1><p>Welcome back.</p>",
        name=name
    )
```

## Explanation

`render_template_string()` compiles its first argument as Jinja2 template source code. Passing untrusted data through f-string interpolation makes that data part of the source, allowing injection. The fix uses a literal template string with `{{ name }}` as a placeholder, then passes the untrusted value as a context variable in the keyword argument. Jinja2 now treats the input as data to render, not source to execute. The default auto-escaping in Flask's Jinja2 environment also HTML-escapes the value, preventing XSS if the output is used in an HTML context.

## Behaviour changes

The output is identical for safe inputs. For inputs containing Jinja2 syntax characters (curly braces, pipes), the original code would execute them as template code; the fixed code escapes them as literal text. For inputs containing `<`, `>`, `&`, `"`, or `'`, the fixed code HTML-escapes them to entities, which is the correct behaviour for HTML output.
