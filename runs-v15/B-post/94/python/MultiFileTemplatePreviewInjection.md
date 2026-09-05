## Verdict
Exploitable

## Source
User input from `request.json.get("template")` in `template_controller.py` line 11

## Sink
`Environment.from_string(draft.source)` in `template_renderer.py` line 10

## Fix

**Vulnerable Code:**
```python
from jinja2 import Environment

class TemplatePreviewRenderer:
    def __init__(self):
        self.env = Environment(autoescape=True)

    def render_preview(self, draft, context):
        # CWE-94: Untrusted template source compiled without sandboxing
        template = self.env.from_string(draft.source)
        return template.render(context)
```

**Fixed Code:**
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
The vulnerability occurs because `Environment.from_string()` compiles the template source as Jinja2 code, allowing attackers to inject arbitrary template directives and expressions. Even though `autoescape=True` prevents output-level XSS, it does not restrict code execution through template syntax like `{{ ... }}` and `{% ... %}`. The fix replaces the regular `Environment` with `SandboxedEnvironment` from `jinja2.sandbox`, which restricts access to dangerous operations like object attribute traversal, method calls, and imports while still allowing legitimate template rendering. This is the Jinja2 library's supported mechanism for safely rendering user-supplied templates.

## Behaviour changes
None. `SandboxedEnvironment` has the same API as `Environment` and produces identical output for legitimate templates. The only difference is that it blocks access to dangerous Jinja2 features that would enable code injection. The `autoescape` parameter, template syntax, and `render()` method work identically.
