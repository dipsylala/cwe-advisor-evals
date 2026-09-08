## Verdict

exploitable

- cwe_id: CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- location: `greeting.py`, line 18 (sink: `render_template_string` call inside `greet()`)
- confidence: high

## Source

`request.args.get("name", "friend")` at line 15 - the `name` query-string parameter from the `/greet` HTTP endpoint. It is fully attacker-controlled (only a default value is supplied, no validation or escaping), and it flows unmodified into an f-string on the very next executable line.

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

    return render_template_string(
        "<h1>Hello {{ name }}!</h1><p>Welcome back.</p>", name=name
    )


if __name__ == "__main__":
    app.run()
```

## Explanation

The vulnerable code built the Jinja2 template *source* itself with an f-string (`f"<h1>Hello {name}!</h1>..."`), then handed that attacker-influenced source to `render_template_string`, which compiles and executes whatever template syntax it finds. Because `name` is fully attacker-controlled, a value such as `{{ config.items() }}` or a chained-attribute payload reaching `__class__`/`__mro__`/`__subclasses__` is compiled as live Jinja2 syntax and can lead to information disclosure or remote code execution - auto-escaping does not apply because the string was never treated as data, it *was* the template. The fix keeps the template source static (`"<h1>Hello {{ name }}!</h1><p>Welcome back.</p>"`) and passes `name` as a render context variable via the `name=name` keyword argument instead of interpolating it into the template text. Jinja2 now only substitutes the value into the `{{ name }}` expression slot with its default auto-escaping applied, so the string can never be parsed as template syntax, and the output is HTML-escaped as a side benefit, closing the associated CWE-79 exposure at the same sink.

## Behaviour changes

- The `render_template_string` call now receives the template as a fixed literal plus a `name=name` keyword argument, instead of a single pre-interpolated string. The rendered output for ordinary, non-payload names (e.g. `Alex`) is byte-for-byte identical to before.
- The only externally visible difference is that a `name` value containing Jinja2 syntax or HTML metacharacters (e.g. `{{7*7}}`, `<script>`) is now rendered as literal, escaped text instead of being evaluated or injected as raw markup - this is the intended elimination of the weakness, not an unrelated behaviour change.
- No change to the function's return type, status code, default value (`"friend"`), route, or error behavior.

## Verification

`python -m py_compile greeting.py` was run against the fixed file copied to a scratch directory outside the repository; it compiled with no errors or warnings. The only new construct introduced - the `render_template_string(template, **context)` keyword-argument form - is the documented standard usage of the same `flask.render_template_string` function already imported in the original file, so no new import or dependency was added.
