## Verdict

Exploitable. User-controlled template source from HTTP request parameter flows directly to `Environment.from_string()`, allowing arbitrary Jinja2 code execution.

## Source

**File**: `template_controller.py` line 11
```python
template_source = request.json.get("template")
```
Attacker-supplied template string from HTTP request body, passed through `template_store.save_draft()` and stored in `TemplateDraft.source`.

## Fix

**Vulnerable Code** (`template_renderer.py` lines 1-11):
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

**Fixed Code**:
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

The fix replaces the unsafe `Environment` with `SandboxedEnvironment`, which restricts the operations available within templates compiled from untrusted sources. `SandboxedEnvironment` blocks dangerous template operations like accessing attributes, calling methods, or reaching global objects that could be exploited for code execution. This prevents attackers from injecting expressions like `{{ config.items() }}` or accessing application internals through Jinja2's introspection capabilities. The `autoescape=True` setting is preserved to provide XSS defense for template output.

## Behaviour changes

The sandboxed environment restricts template operations:

- **Restricted**: Templates can no longer access object attributes (e.g., `{{ obj.method }}`), call methods, access globals, or use dangerous built-ins
- **Allowed**: Template variables are still accessible (e.g., `{{ user }}`, `{{ campaign }}`), loops and conditionals still work, filters and tests available in the sandbox still work
- **Performance**: Minimal overhead; template rendering is slightly slower due to security checks but negligible for typical template sizes
- **Context compatibility**: The `context` dict passed to `render()` remains unchanged; only template code capabilities are restricted
- **Return value**: `template.render(context)` signature and return type unchanged

The application's preview functionality is preserved; only the dangerous capability to execute arbitrary template code is removed.
