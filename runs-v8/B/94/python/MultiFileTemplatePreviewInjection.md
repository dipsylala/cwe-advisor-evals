## Verdict

exploitable

## Source

User-supplied template source from HTTP request (`request.json.get("template")` in template_controller.py line 11), passed through template_store.py to TemplateDraft.source, then to the vulnerable sink.

## Fix

**Vulnerable code (template_renderer.py line 10):**
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

**Fixed code:**
```python
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment

class TemplatePreviewRenderer:
    def __init__(self):
        self.env = SandboxedEnvironment(autoescape=True)

    def render_preview(self, draft, context):
        template = self.env.from_string(draft.source)
        return template.render(context)
```

## Explanation

The vulnerability occurs because `Environment.from_string()` compiles untrusted user-supplied template source, allowing attackers to inject arbitrary Jinja2 code that executes within the application context. The fix replaces the regular `Environment` with `jinja2.sandbox.SandboxedEnvironment`, which restricts the operations available in templates to prevent access to dangerous methods, attributes, and built-in functions. This enforces a restricted execution context where template code cannot access methods that could be used to break out of the sandbox or access sensitive application state. The fix still requires application-level CPU and memory limits (e.g., request timeouts, max response size) to prevent resource exhaustion attacks through template expansion.

## Behaviour changes

The sandboxed environment restricts Jinja2 template capabilities by default: templates cannot access arbitrary object attributes, call methods on unsafe objects, or use dangerous built-in functions. Any templates currently relying on unrestricted access to Python objects or methods will behave differently. Specifically:
- Template expressions attempting to access object `__class__`, `__bases__`, or other magic attributes will fail
- Method calls on objects outside the sandbox's allowed list will be denied
- Access to built-in functions not explicitly allowed by the sandbox will fail

These are intentional restrictions that close the injection vector. The fix preserves the core templating functionality (variable substitution, loops, conditionals, filters) but disallows the dangerous introspection and method invocation pathways exploited in code injection attacks.
