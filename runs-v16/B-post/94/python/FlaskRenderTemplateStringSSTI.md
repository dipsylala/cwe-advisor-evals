## Verdict

exploitable

## Source

`request.args.get("name", "friend")` at line 15 - HTTP query parameter `name` is attacker-controlled and defaults to "friend" if not supplied.

## Fix

**Vulnerable code (line 18):**
```python
return render_template_string(f"<h1>Hello {name}!</h1><p>Welcome back.</p>")
```

**Fixed code:**
```python
return render_template_string("<h1>Hello {{ name }}!</h1><p>Welcome back.</p>", name=name)
```

## Explanation

The vulnerability occurs because `render_template_string()` compiles its first argument as a Jinja2 template. When the template body contains user input from `name`, an attacker can inject Jinja2 syntax to execute arbitrary code. For example, `?name={{7*7}}` would render as `Hello 49!`, and more dangerously, template filters and variable access could reach Python builtins. The fix moves the user input from the *template source* to *template data*. The template body is now static (controlled by the application), and the name is passed as a context variable via the `name=name` keyword argument. Jinja2 will render `{{ name }}` as a variable reference, automatically HTML-escaping the value, treating any Jinja2 syntax in the name as literal text rather than code to execute.

## Behaviour changes

**Arguments changed:** The `render_template_string()` call now includes `name=name` as a keyword argument in the context dictionary, where it was previously omitted. The original code left the context empty (no kwargs).

**Template source changed:** The f-string with embedded name is replaced with a static template string containing Jinja2 variable placeholder syntax. This is the core of the fix and is required to close the injection: the template source must be under application control, never derived from user input.

**Return value:** Unchanged - still returns the rendered HTML string.

**Jinja2 auto-escaping behavior:** Preserved - Jinja2's default auto-escaping remains active, so any HTML special characters in the name (e.g., `<`, `>`, `&`) will be entity-escaped in the output.

## Verification

Python syntax verification (`python -m py_compile`) passed on the fixed code. No new imports or dependencies introduced - `render_template_string()` and the context-variable passing pattern are already available in Flask's public API (already imported at line 8).

Assumptions: The scope of the fix assumes the user-editable template requirement mentioned in the docstring ("without a static template file per campaign") can be satisfied by varying the *data* (the name parameter) rather than the *template source*. This is both the secure pattern and aligns with the actual use case: rendering a personalized greeting based on a query parameter.

