## Verdict

Confirmed. `Widget.cshtml` writes `Model.Label` into a `<script>` block using `@Html.Raw(...)` inside a hand-built JavaScript string literal.

## Source

`WidgetViewModel.Label` (`WidgetViewModel.cs`) is a plain string property with no server-side origin shown in this chain; it reaches the view as `Model.Label` and is rendered untrusted.

`@Html.Raw(Model.Label)` at `Widget.cshtml` line 7 is the sink: `Html.Raw` explicitly disables Razor's automatic HTML encoding, and the value is placed both inside a double-quoted JS string literal and inside an inline `<script>` element. An attacker-controlled `Label` such as `";alert(document.cookie);//` breaks out of the JS string and executes arbitrary script, and a value such as `</script><script>alert(1)</script>` breaks out of the `<script>` element entirely regardless of the JS quoting. Razor's default `@` encoding would not have helped here either, since it HTML-encodes for markup context, not for a JavaScript string/script-block context - the `Html.Raw` call is what removes the only encoding that was in place.

## Fix

### File: Views/Dashboard/Widget.cshtml
```cshtml
@model WidgetViewModel

<section id="widget-preview">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: @Html.Raw(System.Text.Json.JsonSerializer.Serialize(Model.Label)),
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation

`System.Text.Json.JsonSerializer.Serialize(Model.Label)` produces a fully quoted, JSON-escaped string literal (quotes, backslashes, and control characters are escaped, and the default encoder also escapes HTML-sensitive characters like `<`, `>`, `&`, and `'`), so the result is safe both as a JavaScript string value and against breaking out of the surrounding `<script>` element - a `</script>` inside `Label` is emitted as `</script>` rather than literal markup. `Html.Raw` is still used, but now around trusted, already-escaped JSON output rather than the raw untrusted value, so it no longer disables any protection; the manual surrounding quotes in the object literal are removed since `Serialize` supplies its own. `Model.Title` and `Model.RefreshSeconds` are left unchanged: `Title` is rendered through normal Razor `@` encoding into HTML markup, which is the correct context for it, and `RefreshSeconds` is an `int`, not attacker-controllable as a string.
