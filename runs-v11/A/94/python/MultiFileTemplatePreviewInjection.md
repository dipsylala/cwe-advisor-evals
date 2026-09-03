## Verdict

CONFIRMED. The vulnerability is a CWE-94 code injection flaw where user-supplied template source code is directly compiled and executed by Jinja2's `from_string()` method without validation or sandboxing.

## Source

The vulnerability exists in the call chain:

1. **template_controller.py (line 11)**: User supplies `template_source` via `request.json.get("template")` without validation
2. **template_store.py (line 8-9)**: The untrusted template source is stored as-is
3. **template_renderer.py (line 10)**: The attacker-controlled source is compiled as Jinja2 code via `self.env.from_string(draft.source)`, allowing arbitrary template injection

An attacker can inject malicious Jinja2 syntax such as `{{ __import__('os').system('rm -rf /') }}` or other template directives to achieve code execution or information disclosure.

## Fix

Replace the template compilation approach with one of these remediation strategies:

**Option 1: Use string formatting with safe variable substitution (Recommended)**

```python
class TemplatePreviewRenderer:
    def __init__(self):
        self.env = Environment(autoescape=True)

    def render_preview(self, draft, context):
        # Treat draft.source as a plain string with placeholder variables
        # Use simple string formatting or a safe substitution method instead of Jinja2 compilation
        template_string = draft.source
        for key, value in context.items():
            template_string = template_string.replace("{{ " + key + " }}", str(value))
        return template_string
```

**Option 2: Use a sandboxed Jinja2 environment with restricted features**

```python
from jinja2 import Environment, BaseLoader, Undefined

class TemplatePreviewRenderer:
    def __init__(self):
        # Configure a restricted environment that disables access to dangerous globals
        self.env = Environment(
            autoescape=True,
            loader=BaseLoader(),
            undefined=Undefined
        )
        # Explicitly disable access to __builtins__ and other dangerous objects
        self.env.globals = {}
        # Only allow specific safe filters and globals
        self.env.filters['default'] = lambda x, d: x if x else d
        
    def render_preview(self, draft, context):
        # Compile with restricted context
        template = self.env.from_string(draft.source)
        # Limit context to approved variables only
        safe_context = {k: v for k, v in context.items() if k in ['user', 'campaign']}
        return template.render(safe_context)
```

**Option 3: Validate and whitelist template syntax**

```python
import re
from jinja2 import Environment

class TemplatePreviewRenderer:
    # Whitelist only safe Jinja2 syntax patterns
    SAFE_TEMPLATE_PATTERN = re.compile(r'^[\w\s{%}\.\[\]"\':\-,]*$')
    
    def __init__(self):
        self.env = Environment(autoescape=True)

    def render_preview(self, draft, context):
        # Validate the template source against safe patterns
        if not self._is_safe_template(draft.source):
            raise ValueError("Template contains disallowed syntax")
        
        template = self.env.from_string(draft.source)
        return template.render(context)
    
    def _is_safe_template(self, source):
        # Check for dangerous patterns like function calls, imports, etc.
        dangerous_patterns = [
            r'__\w+__',  # Dunder methods/attributes
            r'\.\_',      # Private attribute access
            r'import',    # Import statements
            r'\(\)',      # Function calls
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, source):
                return False
        return True
```

## Explanation

The core issue is that `Environment.from_string()` compiles arbitrary Jinja2 template syntax, including directives that can access Python objects, call functions, or manipulate the runtime environment. While `autoescape=True` prevents XSS vulnerabilities in *rendered* output, it does not prevent code injection via malicious *template syntax itself*.

For example:
- `{{ __import__('os').system('command') }}` executes shell commands
- `{{ config.__dict__ }}` accesses application configuration
- Custom Jinja2 filters or globals can be exploited if the context includes dangerous objects

**Why each option works:**

- **Option 1** eliminates template compilation entirely for user input, treating it as plain text with variable placeholders
- **Option 2** uses Jinja2's sandboxing but with explicit restrictions on dangerous globals and built-ins
- **Option 3** validates the template source before compilation, rejecting patterns known to enable code injection

**Recommendation:** Option 1 is the safest for a preview feature. If full Jinja2 template support is required, use Option 2 with a sandboxed environment and carefully restrict which context variables are exposed. Option 3 is brittle and prone to bypasses; validation alone is insufficient for this threat model.

Additionally, validate the `template_source` input in the controller before storing it, and consider rate-limiting template compilation to prevent DoS attacks through resource-exhaustive template expressions.
