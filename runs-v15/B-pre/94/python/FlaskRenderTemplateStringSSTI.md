## Verdict

Exploitable. The application passes user-controlled input directly into a Jinja2 template source, allowing arbitrary template injection and code execution.

## Source

`name` parameter from `request.args.get("name", "friend")` on line 15, which is user-supplied via HTTP query string.

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

The vulnerability occurs because `render_template_string()` compiles its argument as a Jinja2 template. When user input is embedded in the template source via an f-string, an attacker can inject template expressions such as `{{ 7*7 }}`, `{{ config }}`, or `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` to execute arbitrary Python code with full application privileges.

The fix removes user input from the template source by using Jinja2 template variables instead. The template source is now static (under application control), and the untrusted `name` value is passed as a context variable to `render_template_string()`. Jinja2 automatically escapes variable substitutions by default, preventing template injection. The attacker's input is now treated as data, not code.

## Behaviour changes

None. The application's external behaviour is identical: a user visiting `/greet?name=Alice` still receives `<h1>Hello Alice!</h1><p>Welcome back.</p>`. The fix changes only the internal mechanism from embedding input in template source to passing it as a template variable, eliminating the code injection vector without altering functionality.
