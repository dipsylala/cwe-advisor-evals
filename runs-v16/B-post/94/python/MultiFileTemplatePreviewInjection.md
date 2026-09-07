## Verdict

VULNERABLE - CWE-94 code injection via untrusted Jinja2 template source.

## Source

User-supplied template source reaches the vulnerable sink through this call chain:

1. HTTP request parameter `template` (template_controller.py:11)
2. Stored in `TemplateDraft.source` (template_store.py:9)
3. Passed as `draft` to `render_preview()` (template_controller.py:16)
4. Accessed as `draft.source` and compiled at the sink (template_renderer.py:10)

## Fix

Replace `Environment` with `SandboxedEnvironment` in template_renderer.py:

**Vulnerable code (line 10):**
```python
from jinja2 import Environment

class TemplatePreviewRenderer:
    def __init__(self):
        self.env = Environment(autoescape=True)

    def render_preview(self, draft, context):
        template = self.env.from_string(draft.source)  # VULNERABLE
        return template.render(context)
```

**Fixed code:**
```python
from jinja2.sandbox import SandboxedEnvironment

class TemplatePreviewRenderer:
    def __init__(self):
        self.env = SandboxedEnvironment(autoescape=True)

    def render_preview(self, draft, context):
        template = self.env.from_string(draft.source)
        return template.render(context)
```

## Explanation

`Environment.from_string()` compiles untrusted template source without restriction, allowing attackers to inject Jinja2 directives (e.g., `{{ config.items() }}`, `{% for item in [].__class__.__bases__ %}`). The `autoescape=True` setting only escapes output data inserted into templates, not the template structure itself.

`SandboxedEnvironment` restricts the operations available inside templates: it blocks access to dangerous attributes, methods, and globals. Attackers can no longer use `__class__`, `__bases__`, or other reflection paths to escape the sandbox and access application internals.

The fix changes only the import and the environment class, preserving the existing `from_string()` call, render behavior, and context passing. The context data passed to `render()` is already restricted to the minimal set required (`user` and `campaign`).

## Behaviour changes

- Template rendering now executes within a restricted namespace that blocks reflection and attribute access paths
- Legitimate templates that do not rely on accessing object internals (attributes like `__class__`, introspection methods) continue to work unchanged
- Malicious template injection (e.g., `{{ config.__class__ }}`, `{% for x in [].__class__.__bases__[0].__subclasses__() %}`) is now blocked
- No change to the public API or return values; rendering still produces the same safe HTML output for legitimate templates
