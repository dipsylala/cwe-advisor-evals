## Verdict

Confirmed. `Widget.cshtml` writes `Model.Label` into a `<script>` block using `@Html.Raw`, which disables Razor's automatic HTML encoding and inserts the value directly into a JavaScript string literal with no JavaScript-context escaping at all. Any caller that lets a user influence `WidgetViewModel.Label` (e.g. a dashboard label, widget title, or similar user-editable field persisted and passed into this view) can break out of the quoted string and inject arbitrary script.

## Source

- Sink: `Views/Dashboard/Widget.cshtml`, line 7 — `label: "@Html.Raw(Model.Label)",` inside an inline `<script>` block.
- Tainted value: `WidgetViewModel.Label` (`WidgetViewModel.cs`, line 6), an unconstrained `string` property with no validation, encoding, or allow-list applied before it reaches the view.
- Data flow: whatever controller/service populates `WidgetViewModel.Label` from request or storage data flows unmodified into the view, and `@Html.Raw` explicitly suppresses Razor's default HTML encoder for that value. Because the injection point is inside a JS string literal (not HTML markup), even Razor's normal auto-encoding (`@Model.Label` without `Html.Raw`) would not fully protect this sink — HTML-encoding does not neutralize `"`, `\`, or `</script>` for a JavaScript-string context.

Example exploit input for `Label`: `x"};alert(document.cookie);//` — this closes the JS string, injects a statement, and comments out the trailing `,`. A value containing `</script><script>alert(1)</script>` breaks out of the `<script>` block entirely.

## Fix

Replace the raw string interpolation with a JSON-serialized value, which handles JS-string escaping and `</script>` breakout in one step, and drop the manual quotes:

```csharp
@model WidgetViewModel
@using System.Text.Json

<section id="widget-preview">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: @Html.Raw(JsonSerializer.Serialize(Model.Label)),
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

`JsonSerializer.Serialize(string)` emits a complete, correctly quoted JSON string token (including the surrounding `"`), escaping `"`, `\`, control characters, and — under the default (non-relaxed) `JavaScriptEncoder`, which `JsonSerializer` uses unless a relaxed encoder is explicitly configured — also escaping `<`, `>`, `&`, and `'` as `\uXXXX` sequences. That closes both the JS-string-breakout path and the `</script>`-tag-breakout path in the same call, so `Html.Raw` is safe here only because its input is now a fully JSON-escaped literal, not the raw untrusted string.

`RefreshSeconds` is an `int` and needs no change.

## Explanation

`@Html.Raw` exists to opt an already-trusted or already-encoded value out of Razor's HTML encoding; using it directly on unvalidated user data defeats the one protection Razor provides by default. Here the deeper problem is that the sink is a JavaScript string literal embedded in an HTML document, a context Razor's HTML encoder was never designed to protect — HTML encoding neutralizes `<`, `>`, and `&` for markup parsing but leaves `"` and `\` untouched, so even `@Model.Label` without `Html.Raw` would let an attacker terminate the JS string with an unescaped quote. The only reliable way to place untrusted data inside inline script is to serialize it through a JSON encoder that understands JS-string and HTML-in-script escaping rules, then mark the resulting token (not the original string) as raw. Prefer this pattern — `Html.Raw(JsonSerializer.Serialize(value))` — for any data crossing from a Razor model into an inline `<script>` block, and prefer moving such data into a non-script HTML attribute (e.g. a `data-*` attribute read by external JS) when the design allows, since that keeps the value inside Razor's default HTML-encoded output path entirely.
