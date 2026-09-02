## Verdict

exploitable (confidence: high)

CWE-94, Improper Control of Generation of Code ('Code Injection'). Sink: `template_renderer.py:10`, `self.env.from_string(draft.source)`, followed by `template.render(context)` on line 11.

## Source

- **Source**: `template_controller.py:11`, `request.json.get("template")` - the raw HTTP request body, fully attacker-controlled.
- **Flow**: `TemplatePreviewController.preview()` reads `template_source` from the request body with no validation, passes it to `TemplateDraftStore.save_draft()` (`template_store.py:8-9`, a pure pass-through that wraps it in a `TemplateDraft` with no sanitization or transformation), and hands the resulting `draft.source` straight to `TemplatePreviewRenderer.render_preview()`.
- **Sink**: `template_renderer.py:10`, `self.env.from_string(draft.source)` compiles the attacker-supplied string as Jinja2 template *source*, then `template.render(context)` on line 11 executes it. `Environment(autoescape=True)` only escapes rendered *output*; it does not restrict what the template body itself can do at compile/render time. An unmodified `Environment` permits full attribute-chain traversal (e.g. reaching `__class__`/`__mro__`/`__subclasses__` from any object in scope, or from Jinja's own globals), so this is a standard server-side template injection (SSTI) path to arbitrary code execution, not just markup injection.
- No allowlist, size cap, or sandboxing sits between source and sink.

## Fix

No library version change is required - `jinja2.sandbox.SandboxedEnvironment` ships in the same `jinja2` package already in use; only the import and instantiation change. Confirm the resolved `jinja2` version against your SCA tooling as a general hygiene check, independent of this fix.

**Vulnerable code** (`template_renderer.py`):

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

**Fixed code** (`template_renderer.py`):

```python
from jinja2.sandbox import SandboxedEnvironment


class TemplatePreviewRenderer:
    def __init__(self):
        self.env = SandboxedEnvironment(autoescape=True)

    def render_preview(self, draft, context):
        template = self.env.from_string(draft.source)
        return template.render(context)
```

`SandboxedEnvironment` restricts unsafe attribute access (blocks underscore-prefixed and internal attributes, so the `__class__`/`__mro__`/`__subclasses__` chain and similar introspection gadgets are rejected), rejects calls to methods/functions marked unsafe, and disallows mutation of passed-in objects from within the template - it is Jinja's documented mechanism for rendering templates whose *source*, not just their data, is untrusted.

The sandbox's own documented preconditions are not fully met by the surrounding code and are called out rather than silently assumed:

**Context passed to the template** (`template_controller.py`), narrowed to what the guidance requires - only the data the template needs, not a live object whose attributes/methods could still be reached inside the sandbox:

```python
    def preview(self, request):
        template_source = request.json.get("template")
        if not template_source:
            return {"error": "template is required"}, 400

        draft = self.store.save_draft(request.user.id, template_source)
        html = self.renderer.render_preview(draft, {
            "user": {"id": request.user.id, "name": getattr(request.user, "display_name", None)},
            "campaign": request.json.get("campaign", {})
        })
        return {"preview": html}, 200
```

## Explanation

The root cause is that `Environment.from_string()` compiles attacker-controlled text as executable template source with no constraints on what that source can do; `autoescape=True` only affects HTML-escaping of rendered output and has no bearing on this. Switching to `jinja2.sandbox.SandboxedEnvironment` closes the primary weakness by rejecting the attribute/method access patterns that make Jinja2 SSTI equivalent to code execution, while preserving the feature (users can still write and preview templates). The context change in the controller addresses the sandbox's second documented precondition: previously the full `request.user` object was passed into the template scope, and even under the sandbox a template can still read any *safe* attribute or call any method not explicitly marked unsafe on an object it's given - passing a plain dict with only the two fields the template needs removes that surface entirely rather than relying on the sandbox to police it object-by-object.

## Behaviour changes

- `self.env` is now a `SandboxedEnvironment` instead of a plain `Environment`: any existing preview template that relies on unsafe attribute access, `__`-prefixed attributes, or calling non-allowlisted methods on passed-in objects (patterns that happened to work under the unrestricted environment) will now raise `jinja2.exceptions.SecurityError` at render time instead of succeeding. This is intended - those are exactly the patterns that made the sink exploitable - but any legitimate template that unintentionally depended on such access will need to be rewritten.
- The `"user"` context value changes from the live `request.user` object to a plain `{"id": ..., "name": ...}` dict. A template that references `user.id` or `user.display_name` (via `user.name` after this change) continues to work; a template referencing any other attribute or method of `request.user` will now see `Undefined` instead of a real value. This narrowing is a direct requirement of the guidance's sandboxing precondition ("pass only the data the template needs rather than globals or objects whose methods have side effects"), not incidental scope creep.
- Not addressed in code: the loaded guidance also calls for running sandboxed rendering under CPU and memory limits, since a crafted-but-otherwise-safe template can still expand to very large output or loop expensively within the sandbox's allowed operations. Jinja2 provides no built-in mechanism for this; it needs to come from outside the interpreter (a per-request timeout, a memory-limited worker/subprocess, or equivalent platform-level constraint) and is left as an infrastructure-level follow-up rather than a change to this file.
- Sink contract otherwise preserved: `render_preview()` still returns a string via `template.render(context)`, and `preview()` still returns `{"preview": html}, 200` on success and `{"error": ...}, 400` when the template is missing; failure behaviour (a malformed template still raises `TemplateSyntaxError`/`SecurityError`, uncaught, exactly as the original raised `TemplateSyntaxError`/`UndefinedError` uncaught) is unchanged.
