## Verdict
Confirmed CWE-94: Code Injection via untrusted Jinja2 template compilation.

## Source
In `template_renderer.py` line 10, the `draft.source` (derived from user input via the request body) is compiled as a Jinja2 template string without restriction:

```python
template = self.env.from_string(draft.source)
```

The call chain is: `request.json.get("template")` → `store.save_draft(template_source)` → `renderer.render_preview(draft, context)` → `env.from_string(draft.source)`.

Although `autoescape=True` is set, autoescape only escapes rendered output to prevent XSS—it does not restrict template syntax and does not prevent template injection attacks. An attacker can inject arbitrary Jinja2 expressions like `{{ __import__('os').system('id') }}` into the template string to execute code at template compilation time.

## Fix
Replace `Environment` with `SandboxedEnvironment` from `jinja2.sandbox`:

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
`SandboxedEnvironment` restricts the template syntax to prevent access to dangerous Python features like `__import__`, attribute access via `.__dict__`, and other code execution primitives. This allows Jinja2's powerful templating features to remain available while blocking the injection vectors that CWE-94 exploits.

The autoescape setting is preserved to continue preventing XSS in the rendered output. With this change, user-supplied template strings are safe to compile because the sandbox prevents execution of arbitrary code, regardless of what expressions are embedded in the template.
