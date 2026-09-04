## Verdict

Confirmed: CWE-94 Code Injection via untrusted Jinja2 template source

## Source

`template_controller.py` line 11: `template_source = request.json.get("template")` - attacker-supplied template source accepted directly from HTTP request

## Fix

Replace `Environment` with `jinja2.sandbox.SandboxedEnvironment` in `template_renderer.py`:

```python
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment

class TemplatePreviewRenderer:
    def __init__(self):
        self.env = SandboxedEnvironment(autoescape=True)

    def render_preview(self, draft, context):
        # Using SandboxedEnvironment restricts template directives
        template = self.env.from_string(draft.source)
        return template.render(context)
```

## Explanation

The original code uses `jinja2.Environment.from_string()` with untrusted template source from the HTTP request. Although `autoescape=True` is configured, autoescape only escapes variables within templates, not the template structure itself. An attacker can inject Jinja2 template directives (e.g., `{{ config.items() }}`, loops, or imports) to execute arbitrary code with full access to the application's runtime.

`SandboxedEnvironment` restricts the template engine's capabilities: it disables access to dangerous functions and attributes, preventing introspection and method invocation that could reach internal Python objects. This is the recommended pattern for rendering untrusted template sources in Jinja2, and is explicitly documented in the Jinja2 project as the way to safely handle user-supplied templates.

The change preserves the existing behavior (autoescape still works for variables, template rendering returns the same output type) while eliminating the injection vector.

## Behaviour changes

- Template directives that rely on unsafe Python object access are now rejected (calls to `__class__`, attribute traversal beyond whitelisted attributes)
- Template output for safe, well-formed templates remains identical
- Malicious templates that attempt to access internals or execute code now raise an error during rendering instead of succeeding
