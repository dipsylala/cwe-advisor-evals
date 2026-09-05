## Verdict

Exploitable. The `draft.source` parameter originates from untrusted HTTP request input (`request.json.get("template")` in template_controller.py line 11) and flows directly to `self.env.from_string(draft.source)` at template_renderer.py line 10 without validation or sanitization. An attacker can submit arbitrary Jinja2 template syntax to execute code within the application's template engine context.

## Source

`request.json.get("template")` → `template_controller.py` line 11 → `save_draft()` → `draft.source` property → `template_renderer.py` line 10

The untrusted template source enters through an HTTP request parameter and is stored in a `TemplateDraft` object, then passed to the vulnerable sink without any constraints.

## Fix

**Vulnerable Code:**
```python
from jinja2 import Environment


class TemplatePreviewRenderer:
    def __init__(self):
        self.env = Environment(autoescape=True)

    def render_preview(self, draft, context):
        # SAST FINDING: CWE-94 (Improper Control of Generation of Code) reported here. Sink is the next statement.
        template = self.env.from_string(draft.source)
        return template.render(context)
```

**Fixed Code:**
```python
from jinja2 import SandboxedEnvironment


class TemplatePreviewRenderer:
    def __init__(self):
        self.env = SandboxedEnvironment(autoescape=True)

    def render_preview(self, draft, context):
        # SAST FINDING: CWE-94 (Improper Control of Generation of Code) reported here. Sink is the next statement.
        template = self.env.from_string(draft.source)
        return template.render(context)
```

## Explanation

Replace `Environment` with `SandboxedEnvironment` in both the import and the constructor. `SandboxedEnvironment` is a Jinja2 built-in sandbox designed specifically for rendering untrusted templates. It restricts template access to dangerous introspection mechanisms, preventing attackers from reaching Python builtins, class hierarchies, and other privileged functionality through template syntax. The `autoescape=True` setting is preserved to prevent XSS in template data values. The interface remains identical—no changes to method calls or logic are required. This addresses the CWE-94 weakness by allowing user-supplied template source to be processed safely within a restricted execution context.

## Behaviour changes

None. `SandboxedEnvironment` provides the same `from_string()` and `render()` interface as `Environment`. The change restricts what the template can access (blocks introspection and dangerous attributes), but does not alter return values, error behavior, or the contract of the `render_preview()` method. The autoescape behavior is identical.
