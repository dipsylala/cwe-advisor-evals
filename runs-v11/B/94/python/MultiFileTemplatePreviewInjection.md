## Verdict

Real code injection vulnerability. Untrusted Jinja2 template source from HTTP request is compiled and executed without restrictions.

## Source

**Entry point**: `template_controller.py` line 11
```python
template_source = request.json.get("template")
```

Attacker-controlled data from HTTP request JSON body, passed to `store.save_draft()` and stored in `draft.source`.

## Fix

Replace `jinja2.Environment` with `jinja2.sandbox.SandboxedEnvironment` to restrict template execution:

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

`Environment.from_string()` compiles the template string as executable Jinja2 code, allowing attackers to inject expressions like `{{ __import__('os').system('id') }}` that access Python builtins and execute arbitrary code.

`SandboxedEnvironment` restricts template execution by preventing access to dangerous attributes and builtins. It blocks attribute access (unless explicitly whitelisted), prevents calling arbitrary methods, and disables import statements within templates. An attacker's template is still compiled and rendered, but the sandboxed context prevents it from accessing Python internals or executing system commands.

The `context` dict parameter already provides only the data the template needs (`user` and `campaign` objects from line 16-19 of template_controller.py), so the template cannot access globals or unintended objects.

## Behaviour changes

- Templates can no longer access Python builtins or import modules
- Attribute access on context objects is restricted to safe attributes (blocks accessing `__class__`, `__globals__`, method internals, etc.)
- Legitimate template rendering (variable substitution, filters, loops over provided context) continues to work
- Memory and CPU usage remain unchanged (no timeout/limit wrapper needed in this fix, though production deployments should add those separately)
