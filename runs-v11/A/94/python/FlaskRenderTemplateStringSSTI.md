## Verdict
Real vulnerability. User-controlled input from the query string is interpolated directly into a Jinja2 template string, allowing server-side template injection.

## Source
The `name` parameter originates from `request.args.get("name", "friend")` at line 15, which reads from the URL query string without validation. At line 18, this untrusted value is embedded directly into a Jinja2 template via f-string interpolation before being passed to `render_template_string()`. An attacker can inject template directives such as `{{7*7}}` or `{{config}}` to execute arbitrary code.

## Fix
Replace the f-string template interpolation with a template variable that keeps user input separate from template code:

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    template = "<h1>Hello {{ name }}!</h1><p>Welcome back.</p>"
    return render_template_string(template, name=name)

if __name__ == "__main__":
    app.run()
```

## Explanation
The fix uses Jinja2's variable substitution (`{{ name }}`) instead of Python f-string interpolation. By passing `name` as a template variable argument to `render_template_string()`, Jinja2 automatically escapes the value as data, not executable template code. An attacker's input like `{{7*7}}` will now render literally as text rather than being evaluated as a template expression. This enforces the intended separation: the template structure is trusted code, and the user input is untrusted data.
