## Verdict

Vulnerable. The `draft.source` parameter is attacker-controlled input from an HTTP request that flows directly to `Environment.from_string()`, which compiles and executes arbitrary Jinja2 template code.

## Source

Data flow traced across three files in the call chain:

1. **template_controller.py** (line 11): `template_source = request.json.get("template")`
   - Untrusted input from HTTP request JSON body

2. **template_controller.py** (line 15): `draft = self.store.save_draft(request.user.id, template_source)`
   - Passes untrusted template source to store

3. **template_store.py** (line 9): `return TemplateDraft(owner_id, source)`
   - Wraps source in TemplateDraft object without validation

4. **template_controller.py** (line 16): `self.renderer.render_preview(draft, {...})`
   - Passes draft to renderer

5. **template_renderer.py** (line 10): `template = self.env.from_string(draft.source)` ← **Sink**
   - `Environment.from_string()` compiles template body from untrusted input

The sink `Environment.from_string()` at line 10 executes the attacker-supplied template code with full Jinja2 evaluation capabilities.

## Fix

### File: template_renderer.py

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

The vulnerability arises because `Environment.from_string()` compiles the template body parameter directly, allowing attackers to inject Jinja2 expressions and directives. While `autoescape=True` escapes template output variables, it does not restrict what the template code itself can do—an attacker can access object attributes through Jinja2's attribute resolution (e.g., `{{ user.__class__ }}`), iterate through properties, or invoke methods, leading to information disclosure or code execution.

The fix replaces `Environment` with `SandboxedEnvironment`, which is specifically designed for untrusted templates. `SandboxedEnvironment` restricts the operations available within template evaluation by:
- Preventing access to object constructors and type introspection
- Disallowing direct calls to Python built-in functions
- Blocking attribute access to methods with side effects or security implications
- Limiting the available namespace to explicitly passed context variables and safe filters

The `autoescape=True` setting is preserved to ensure output variables are safely escaped, providing defense-in-depth.

## Behaviour changes

**What changes:**
- Templates now execute in a restricted sandbox that prevents dangerous introspection and method calls
- Legitimate template syntax (variable substitution, filters, loops, conditionals) continues to work

**What no longer works in templates:**
- Accessing arbitrary object attributes via dot notation beyond the explicitly passed context
- Calling Python built-in functions or unsafe methods
- Accessing object `__class__`, `__bases__`, or other dunder attributes
- Creating new objects or accessing type constructors

**Impact on the application:**
- The template preview feature remains functional for normal template content
- Applications currently relying on passing complex objects with unsafe methods callable from templates will need to create wrapper objects or custom filters
- The context passed in line 18-19 of template_controller.py (`request.user` and `campaign` dict) will still be accessible via normal Jinja2 variable substitution (e.g., `{{ user.name }}`), but direct method invocation on those objects is blocked
