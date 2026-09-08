## Verdict

Confirmed exploitable. CWE-94 (Improper Control of Generation of Code), classic Server-Side Template Injection (SSTI) via Jinja2.

## Source

`template_controller.py`, `TemplatePreviewController.preview()`: `template_source = request.json.get("template")` - the raw HTTP request body, fully attacker-controlled.

Call chain:

1. `TemplatePreviewController.preview(request)` reads `template_source` from `request.json` and passes it to `self.store.save_draft(request.user.id, template_source)`.
2. `TemplateDraftStore.save_draft()` (`template_store.py`) wraps it unchanged in a `TemplateDraft(owner_id, source)` - no validation, encoding, or transformation occurs here.
3. `TemplatePreviewController.preview()` then calls `self.renderer.render_preview(draft, {...})`.
4. `TemplatePreviewRenderer.render_preview()` (`template_renderer.py`, line 10) calls `self.env.from_string(draft.source)` - this compiles `draft.source` (the untouched attacker input) as Jinja2 template *source*, then renders it via `template.render(context)`.

Nothing on this path constrains, escapes, or sandboxes the template body before compilation. `Environment(autoescape=True)` only auto-escapes *variable output* injected into an already-trusted template; it does not restrict what the template *source itself* can do. Because the environment is a full `jinja2.Environment`, a submitted "template" containing an expression such as `{{ ''.__class__.__mro__[1].__subclasses__() }}` reaches Python's class hierarchy from the sandboxed-looking preview endpoint, giving arbitrary code execution in the application process. The finding is exploitable exactly as reported.

## Fix

### File: template_renderer.py
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

The endpoint's own purpose is to let a user submit and preview an arbitrary Jinja2 template body, so removing dynamic template compilation entirely is not an option here - this is the "user-editable templates are a genuine requirement" case the knowledge base calls out. The fix swaps `jinja2.Environment` for `jinja2.sandbox.SandboxedEnvironment`, which Jinja2 ships specifically for compiling and rendering untrusted template source. `SandboxedEnvironment` intercepts attribute/item access and blocks anything Jinja2 classifies as unsafe - notably any attribute or item name starting with `_` (which closes off `__class__`, `__mro__`, `__subclasses__`, `__globals__`, and the rest of the introspection chain attackers use to reach arbitrary classes from a plain string or int) - and refuses to call any callable marked `unsafe_callable` or `alters_data`. Verified directly: rendering `{{ ''.__class__.__mro__[1].__subclasses__() }}` under `SandboxedEnvironment(autoescape=True)` now raises `jinja2.exceptions.SecurityError: access to attribute '__class__' of 'str' object is unsafe` instead of returning the class list, while a normal template (`Hello {{ name }}`) still renders correctly. Nothing else in the call chain changed: `from_string()` and `render()` are called with the same arguments as before, `autoescape=True` is preserved, and the return value/caller contract (`{"preview": html}, 200`) and error propagation (an invalid or sandbox-violating template still raises an exception that the controller does not catch, matching the original's behavior on a malformed template) are unchanged.

One residual point the knowledge base flags as a precondition for this pattern, which this fix does not change: `context` still includes the full `request.user` object (built in `template_controller.py`), not a narrowed set of fields. `SandboxedEnvironment` blocks underscore-prefixed access and anything explicitly marked `alters_data`/`unsafe_callable`, but it does not know which public methods on an arbitrary application object are safe to invoke from a template - if `request.user` (or objects reachable from it) expose a public method with a side effect that isn't marked `alters_data`, a crafted template could still call it. Confirming and narrowing exactly which user fields the preview template needs requires knowledge of the `User` model that isn't available from this call chain, so no attribute names were guessed here; this is flagged rather than silently "fixed" with an unverified field list. Likewise, `SandboxedEnvironment` does not impose CPU or memory limits on its own - a pathological template (e.g. deep recursion or a large loop) can still exhaust resources - and Jinja2's own documentation lists per-request CPU/memory limits as a companion control for genuinely untrusted templates; that is an infrastructure-level control (process timeout/resource cap around the render call) outside this file's scope and is not implemented here.

Verification performed: `python -m py_compile` on the fixed file (passed), plus a runtime check against the installed Jinja2 confirming the sandbox blocks the classic `__class__`/`__mro__`/`__subclasses__` escape while leaving normal variable rendering intact.

## Behaviour changes

- Template rendering now goes through `SandboxedEnvironment` instead of `Environment`. Any legitimate template that relies on accessing dunder/underscore-prefixed attributes, calling a method flagged `alters_data`, or otherwise doing something Jinja2's sandbox classifies as unsafe will now raise `jinja2.exceptions.SecurityError` at render time instead of succeeding - this is expected and is the control closing the vulnerability, but it is a behavior change for any pre-existing draft template that depended on such access.
- No change to the public API, arguments, return values, or `autoescape` setting of `TemplatePreviewRenderer.render_preview()`.
- `template_controller.py` and `template_store.py` are unchanged; the context passed to rendering still includes the full `request.user` object (see caveat in Explanation) and is not narrowed by this fix.
- No resource/time limit was added around the render call; a pathological (but non-introspective) template can still consume excessive CPU/memory.
