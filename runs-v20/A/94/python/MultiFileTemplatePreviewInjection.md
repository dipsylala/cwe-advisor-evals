## Verdict

Confirmed. `render_preview` compiles attacker-controlled text as executable Jinja2 template source, giving a caller server-side template injection (SSTI) that reaches arbitrary Python execution - a textbook CWE-94 code-injection sink, not merely an output-escaping gap.

## Source

- `template_controller.py`: `template_source = request.json.get("template")` reads the template body directly from the request payload with no restriction on its content, then passes it unchanged into `self.store.save_draft(request.user.id, template_source)`.
- `template_store.py`: `TemplateDraftStore.save_draft` wraps the raw string in a `TemplateDraft` without any transformation, so `draft.source` still holds the caller-supplied text verbatim.
- `template_renderer.py` (sink): `self.env.from_string(draft.source)` compiles that untrusted string as Jinja2 template source using a plain `jinja2.Environment`, and the following `template.render(context)` executes it. `autoescape=True` only HTML-escapes the *values substituted into* the template - it does nothing to restrict what the template's own control structures and expressions can do. A plain `Environment` lets an attacker reach Python internals through attribute-chain expressions such as `{{ ''.__class__.__mro__[1].__subclasses__() }}` or similar gadget chains that end in code execution (e.g. spawning a subprocess), fully independent of the `context` dict that is passed in.

## Fix

### File: template_renderer.py
```python
from jinja2.sandbox import ImmutableSandboxedEnvironment


class TemplatePreviewRenderer:
    def __init__(self):
        self.env = ImmutableSandboxedEnvironment(autoescape=True)

    def render_preview(self, draft, context):
        # draft.source is caller-authored template text (see template_controller.py),
        # so it must never be compiled with a plain jinja2.Environment: that class
        # permits attribute-chain expressions (e.g. reaching __class__/__mro__/
        # __globals__) that execute arbitrary Python regardless of autoescape.
        # ImmutableSandboxedEnvironment restricts attribute/method access to a safe
        # allowlist and also blocks in-place mutation of objects placed in the
        # render context (context includes the live request.user object).
        template = self.env.from_string(draft.source)
        return template.render(context)
```

## Explanation

The fix keeps the feature (users compose and preview their own template markup) but stops the compiled template from executing beyond Jinja2's expression language. `SandboxedEnvironment`/`ImmutableSandboxedEnvironment` intercept attribute and item lookups against a safety policy that rejects underscore-prefixed names and other unsafe attributes, and reject calls to methods flagged unsafe (e.g. mutating built-ins), which closes the standard `__class__`/`__globals__`/`__subclasses__` gadget chains used to escape a template sandbox and reach `os`/`subprocess`. The immutable variant additionally blocks calls that would mutate objects handed to the template through `context` (here, the live `request.user` instance), which matters because that object is real application state, not a throwaway value. `autoescape=True` is retained because it is an orthogonal, still-useful defense against reflected markup in substituted values, but it was never the control that mattered for this finding.

This mitigation is not absolute on its own: treat Jinja2's sandbox as a hardening boundary, not a guarantee, and pin the dependency to at least 3.1.6 - a sandbox-escape bypass reachable through the `|attr` filter combined with `str.format` (CVE-2024-56326) was fixed in 3.1.5, and a further bypass of that same fix (CVE-2025-27516) required 3.1.6. An older pinned Jinja2 release would leave the sandbox itself defeatable even after this code change, so a dependency/SCA check on the installed `jinja2` version is part of completing this remediation.
