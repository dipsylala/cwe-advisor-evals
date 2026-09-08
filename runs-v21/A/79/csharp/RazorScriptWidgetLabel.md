## Verdict

The vulnerability is confirmed. Line 7 uses `Html.Raw()` to directly embed `Model.Label` into JavaScript code without encoding, allowing script injection via untrusted string content.

## Source

**File:** Views/Dashboard/Widget.cshtml, line 7

**Vulnerable code:**
```
label: "@Html.Raw(Model.Label)",
```

**Data flow:** User-supplied `Model.Label` (from WidgetViewModel) flows unencoded into a JavaScript object literal within a `<script>` tag.

**Attack vector:** A label value like `"; alert('xss'); "` breaks out of the string context and executes arbitrary JavaScript in the page.

## Fix

### File: Views/Dashboard/Widget.cshtml

```cshtml
@model WidgetViewModel

<section id="widget-preview">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: @System.Text.Json.JsonSerializer.Serialize(Model.Label),
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation

The fix replaces `@Html.Raw(Model.Label)` with `@System.Text.Json.JsonSerializer.Serialize(Model.Label)`, which properly encodes the string for JSON context.

**Why this works:**
- `JsonSerializer.Serialize()` escapes special characters (quotes, backslashes, control characters) and wraps the result in double quotes
- The output is valid JSON and safe to embed in JavaScript
- An attack payload like `"; alert('xss'); "` becomes the JSON string `"\"; alert('xss'); \"" ` (with proper escaping), which is a literal string value, not executable code

**Why the original was vulnerable:**
- `Html.Raw()` disables HTML encoding entirely
- Placing unencoded user input into a JavaScript context allows metacharacter injection (quotes, semicolons) that break out of the string literal
- HTML encoding alone is insufficient for JavaScript contexts; JSON encoding is required

