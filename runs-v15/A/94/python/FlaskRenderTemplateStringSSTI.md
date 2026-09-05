## Verdict

Vulnerable. User-supplied input from `request.args.get("name")` is directly interpolated into an f-string and passed to `render_template_string()`, allowing an attacker to inject Jinja2 template expressions for code execution.

## Source

```python
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string(f"<h1>Hello {name}!</h1><p>Welcome back.</p>")
```

The attacker can supply `name={{7*7}}` to inject template expressions or `name={{self.__init__.__globals__.__builtins__.__import__('os').system('cmd')}}` for arbitrary code execution.

## Fix

```python
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string("<h1>Hello {{ name }}!</h1><p>Welcome back.</p>", name=name)
```

Alternatively, use a static template file and `render_template()`:

```python
# Create templates/greet.html with: <h1>Hello {{ name }}!</h1><p>Welcome back.</p>

@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template("greet.html", name=name)
```

## Explanation

The vulnerability occurs because `render_template_string()` treats the entire f-string template as Jinja2 code. By directly embedding `{name}` via f-string interpolation, the attacker-supplied value is already substituted before Jinja2 parsing—but modern Jinja2 with `render_template_string()` still processes the final string, allowing injection of template syntax like `{{ }}` or `{% %}`.

The fix separates static template structure from user data by passing the name as a template variable via the context dictionary. Flask's Jinja2 integration automatically escapes variable values by default, preventing template injection. The variable `{{ name }}` is treated as a placeholder to be filled with the user input, not as code to execute.

This follows the principle: never pass unsanitized user input directly into template rendering APIs. Always separate template structure from dynamic data through context variables.
