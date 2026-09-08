## Verdict

The vulnerability is exploitable. User input from `request.args.get("name")` is embedded directly into an f-string and passed as template source to `flask.render_template_string()`. An attacker can inject Jinja2 template expressions to execute arbitrary code or cause denial of service.

## Source

**File:** `greeting.py`  
**Line:** 18  
**Function:** `greet()`

Data flow:
1. Line 16: `name = request.args.get("name", "friend")` — HTTP query parameter (untrusted)
2. Line 18: `return render_template_string(f"<h1>Hello {name}!</h1><p>Welcome back.</p>")` — template source includes untrusted `name` via f-string

**Sink:** `flask.render_template_string()` — compiles and evaluates Jinja2 template expressions in the supplied template string.

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
    return render_template_string("<h1>Hello {{ name }}!</h1><p>Welcome back.</p>", name=name)


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix separates template source from data. The template string is now a literal string controlled by the application, not an f-string that embeds user input. The untrusted `name` value is passed as a Jinja2 context variable via the `name=name` keyword argument to `render_template_string()`. When Jinja2 renders `{{ name }}`, it substitutes the variable and applies auto-escaping by default, which neutralizes any HTML tags or Jinja2 syntax the attacker supplies. The function's return value and behavior remain identical for legitimate inputs.

## Behaviour changes

**Before fix:**
- `/greet?name=Alice` → `<h1>Hello Alice!</h1><p>Welcome back.</p>` ✓ (legitimate)
- `/greet?name={{ 7*7 }}` → `<h1>Hello 49!</h1><p>Welcome back.</p>` ✗ (expression evaluated)
- `/greet?name={{config}}` → Template error or information disclosure ✗ (code execution)

**After fix:**
- `/greet?name=Alice` → `<h1>Hello Alice!</h1><p>Welcome back.</p>` ✓ (identical)
- `/greet?name={{ 7*7 }}` → `<h1>Hello {{ 7*7 }}!</h1><p>Welcome back.</p>` ✓ (escaped, displayed as literal text)
- `/greet?name={{config}}` → `<h1>Hello {{config}}!</h1><p>Welcome back.</p>` ✓ (escaped, no code execution)

The fix eliminates template injection while preserving the intended functionality for all legitimate names.
