## Verdict
CONFIRMED - CWE-94 (Improper Control of Generation of Code) via Jinja2 template injection.

## Source
The call chain:
1. `template_controller.py` line 11: `template_source = request.json.get("template")` — untrusted user input
2. `template_controller.py` line 15: `draft = self.store.save_draft(request.user.id, template_source)` — passed to store without validation
3. `template_renderer.py` line 10: `template = self.env.from_string(draft.source)` — **Vulnerability**: user input is compiled as Jinja2 template code

The vulnerability permits a user to inject arbitrary Jinja2 template directives by submitting malicious template syntax in the JSON request body.

## Fix
Replace `Environment.from_string()` with literal string rendering. User-provided input must not be treated as template source code:

```python
from jinja2 import Environment

class TemplatePreviewRenderer:
    def __init__(self):
        self.env = Environment(autoescape=True)

    def render_preview(self, draft, context):
        # Treat draft.source as literal text, not as Jinja2 template code
        template = self.env.from_string("{{ content }}")
        return template.render({"content": draft.source, **context})
```

Alternatively, if template syntax support is a genuine requirement, implement a whitelist-based validation that rejects any input containing Jinja2 directives (`{%`, `{{`, `{#`) before passing to `from_string()`.

## Explanation
CWE-94 occurs when user-controlled data is compiled as code without validation. Here, `Environment.from_string(draft.source)` treats the user-supplied string as Jinja2 template syntax and executes it. This bypasses the intended template scope and permits:
- Access to objects in the rendering context (e.g., `{{ user.__dict__ }}`)
- Calls to built-in Jinja2 functions and filters that may expose sensitive data
- Potential code execution if Jinja2 is configured with unrestricted globals

The `autoescape=True` setting only escapes HTML in rendered output; it does not prevent template syntax injection.

The fix wraps the user input as a literal string value passed to a safe template, preventing interpretation of template syntax. This preserves the preview functionality while eliminating code injection.
