## Verdict
Confirmed XSS vulnerability via unsafe output of user-controlled data into JavaScript context.

## Source
**File**: Views/Dashboard/Widget.cshtml, Line 7

The `Model.Label` property originates from the `WidgetViewModel` class and is user-controlled data. It is output directly into a JavaScript object literal using `@Html.Raw()`, which bypasses HTML encoding. An attacker can break out of the string by injecting a quote character followed by arbitrary JavaScript code.

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
The fix replaces `@Html.Raw(Model.Label)` with `@Html.Raw(System.Text.Json.JsonSerializer.Serialize(Model.Label))`. This approach:

1. **JSON-encodes the string**: `JsonSerializer.Serialize()` properly escapes special characters (including quotes, backslashes, newlines) and wraps the value in quotes, producing a JavaScript-safe string literal.

2. **Preserves quotes in output**: Unlike HTML encoding alone, JSON encoding handles the JavaScript context correctly, escaping characters that would break out of the string literal (e.g., `"` becomes `\"`).

3. **Prevents script injection**: An attacker's attempt to inject `"; alert('xss'); "` becomes the JSON-escaped string `"\"; alert('xss'); \""`—a literal string value inside the object, not executable code.

The `Html.Raw()` wrapper remains because `JsonSerializer.Serialize()` already produces a quoted, escaped, JavaScript-safe string that does not need further encoding.
