## Verdict

Exploitable. CWE-79, Improper Neutralization of Input During Web Page Generation (Cross-Site Scripting) - script-context injection via `@Html.Raw()` into an inline `<script>` block. Confidence: medium - the two-file call chain provided stops at the view model and does not include the controller/action that populates `Label`, so the untrusted origin is an assumption rather than a directly observed source (see Source).

## Source

`WidgetViewModel.Label` (`WidgetViewModel.cs`, line 6: `public string Label { get; init; } = "";`) flows unmodified to `Views/Dashboard/Widget.cshtml` line 7:

```
label: "@Html.Raw(Model.Label)",
```

This is inside an inline `<script>` block, inside a double-quoted JavaScript string literal. `@Html.Raw()` returns its argument as `IHtmlContent`/raw markup, writing it into the response verbatim - it performs no encoding, discards nothing, and has no failure path (it always emits exactly what it is given). Razor's default `@Model.Label` (without `Html.Raw`) would not fully fix this either: that applies Razor's HTML-attribute encoding, which is the wrong encoding for a JS string-literal context - it does not escape backslashes, embedded double quotes, or the JS line terminators U+2028/U+2029, so a value can still break out of the string literal even when HTML-encoded.

Assumption (autonomous mode, no controller in scope to confirm): `Label` is attacker-influenced - the common pattern for a `*Label` field on a per-user/per-tenant dashboard widget is that it is set from user-supplied configuration (e.g. a "rename this widget" form) and persisted, then rendered back on every dashboard load. Treated as untrusted per CWE-79 guidance ("treat all external sources as untrusted").

## Fix

No third-party library is needed; the replacement API is part of the .NET base class library (`System.Text.Encodings.Web`, in-box since .NET Core), so no version/manifest change applies.

Vulnerable (`Views/Dashboard/Widget.cshtml`):

```
@model WidgetViewModel

<section id="widget-preview">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: "@Html.Raw(Model.Label)",
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

Fixed:

```
@using System.Text.Encodings.Web
@model WidgetViewModel

<section id="widget-preview">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: "@JavaScriptEncoder.Default.Encode(Model.Label)",
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation

The fix replaces `@Html.Raw(Model.Label)`, which writes `Label` into the JS string literal with no encoding at all, with `@JavaScriptEncoder.Default.Encode(Model.Label)`, the JS-context encoder the CWE-79 C# guidance names as the fallback when a value cannot be moved out of script source entirely (moving it to a `data-*` attribute and reading it via the DOM, Microsoft's first recommendation, would require restructuring the markup and the inline script's read of `widgetConfig.label`, which is avoided here to keep the change scoped to the sink). `JavaScriptEncoder.Default.Encode()` escapes characters that are meaningful inside a JS string literal - `"`, `\`, `<`, `>`, `&`, and the U+2028/U+2029 line terminators - so an attacker-supplied `Label` such as `"};alert(document.cookie);//` can no longer terminate the string literal or the object literal and inject executable script. `Html.Raw` is exactly the kind of "raw"-named API the CWE-79 guidance flags as a sanitized-input-only sink, and this was the only place untrusted data reached it.

## Behaviour changes

- `@Html.Raw(Model.Label)` -> `@JavaScriptEncoder.Default.Encode(Model.Label)`: this is the fix itself - it now JS-string-escapes `Label` instead of emitting it unmodified. For a legitimate label (no quotes, backslashes, or angle brackets) the emitted string is unchanged; for a label containing those characters, the emitted `widgetConfig.label` value now contains their escaped (`\"`, `\\`, `<`, etc.) forms rather than the literal characters, which is the intended and required behavior change to close the weakness.
- Added `@using System.Text.Encodings.Web`: brings `JavaScriptEncoder` into scope; a compile-time addition only, no runtime effect.
- `<h2>@Model.Title</h2>` and `refreshSeconds: @Model.RefreshSeconds` are unchanged: `Title` is already routed through Razor's default HTML-attribute encoding, which is the correct encoder for its HTML-body context, and `RefreshSeconds` is a non-string `int`, not a string-injection vector.
- No other argument, return value, or error-handling behavior of the surrounding code was altered.
