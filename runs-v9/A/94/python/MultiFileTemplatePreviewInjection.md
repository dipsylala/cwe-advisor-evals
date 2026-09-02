## Verdict

Confirmed. `TemplatePreviewRenderer.render_preview` compiles attacker-controlled text as executable Jinja2 template source, giving a client full server-side template injection (SSTI), which on Jinja2 extends to remote code execution.

## Source

`template_controller.py:11` reads `template_source = request.json.get("template")` directly from the incoming HTTP request body with no validation, length limit, or content restriction. It flows unchanged through `store.save_draft()` (`template_store.py:8-9`, a plain pass-through that copies `source` onto a `TemplateDraft` object) into `renderer.render_preview(draft, ...)` at `template_controller.py:16`, arriving at the sink as `draft.source`.

## Fix

In `template_renderer.py`, replace the plain `jinja2.Environment` with a sandboxed one and keep it locked down:

```python
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import StrictUndefined


class TemplatePreviewRenderer:
    def __init__(self):
        self.env = SandboxedEnvironment(
            autoescape=True,
            undefined=StrictUndefined,
        )
        # Strip anything that lets a sandboxed template reach back into
        # Python internals or the process environment.
        self.env.globals.clear()
        self.env.filters.pop("attr", None)

    def render_preview(self, draft, context):
        template = self.env.from_string(draft.source)
        return template.render(context)
```

`SandboxedEnvironment` intercepts attribute/item access and blocks the `__class__` / `__mro__` / `__subclasses__` gadget chains that a plain `Environment` allows, which is what turns "render this Jinja2 string" into arbitrary code execution. Clearing `env.globals` removes built-ins such as `range`, `lipsum`, and `cycler` that sandbox escapes have historically pivoted through; `autoescape=True` (already present) still only covers HTML output escaping and is unrelated to this fix, so keep it but don't rely on it for the injection itself.

Treat the sandbox as defense-in-depth, not a complete guarantee — Jinja2's sandbox has had documented escape CVEs. Where the product only needs a handful of merge fields (e.g. `user.name`, `campaign.subject`), the stronger fix is to stop compiling user text as a template at all: run the draft through a restricted placeholder substitution (e.g. `string.Template` with a fixed, explicit set of substitution keys, or a simple `{{field}}` regex replace against an allowlisted dict) instead of `Environment.from_string`. Reserve `SandboxedEnvironment` for cases where users genuinely need template-language features (loops, conditionals) in their previews.

Also apply a size cap on `template_source` before it reaches the renderer (e.g. reject anything over a few KB) and a render timeout, since SSTI payloads are frequently used for denial-of-service (e.g. expression-based resource exhaustion) even when code execution is blocked.

## Explanation

Jinja2's default `Environment` compiles the string passed to `from_string()` into executable template bytecode with full access to Python's object model through attribute traversal. Because `draft.source` originates from `request.json.get("template")` with no sanitization, an attacker can submit a payload such as a chain that walks `''.__class__.__mro__` to reach `object.__subclasses__()` and ultimately instantiate something like `subprocess.Popen`, achieving remote code execution on the server that hosts this "preview" endpoint. `autoescape=True` only HTML-escapes values substituted into the output — it does nothing to prevent the template's own control-flow and attribute-access expressions from running, so it does not mitigate this finding. Switching to `SandboxedEnvironment` with globals cleared removes the primary RCE gadget chain by raising `SecurityError` on unsafe attribute access, and combining that with an allowlist-based substitution approach (or a size/timeout cap when the sandbox is still in use) closes the remaining code-execution and resource-exhaustion risk from letting arbitrary users author template source that the server evaluates.
