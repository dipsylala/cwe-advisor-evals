## Verdict

Confirmed. The vulnerability is exploitable: untrusted input from `Model.Label` is embedded directly into a JavaScript string literal using `@Html.Raw()`, allowing an attacker to escape the string and inject JavaScript code.

## Source

`Model.Label` (user-supplied string from WidgetViewModel) flows to the view without validation. The data originates from external sources and should be treated as untrusted.

## Fix

### File: Views/Dashboard/Widget.cshtml

```csharp
@model WidgetViewModel

<section id="widget-preview" data-widget-label="@Model.Label">
    <h2>@Model.Title</h2>
    <script>
        var element = document.getElementById('widget-preview');
        window.widgetConfig = {
            label: element.getAttribute('data-widget-label'),
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation

The original code passed `Model.Label` directly into a JavaScript string literal using `@Html.Raw()`, which bypasses all encoding. An attacker could inject a closing quote followed by JavaScript code to break out of the string and execute arbitrary script (e.g., `", onload: function() { alert("xss") }, "a": "`).

The fix moves the label value to an HTML data attribute (`data-widget-label="@Model.Label"`). Razor's automatic `@` syntax applies HTML attribute encoding to the value, making it safe. The JavaScript code then reads this value at runtime using `getAttribute('data-widget-label')`, which returns the already-decoded string. This approach ensures the untrusted value never crosses into JavaScript source code, following Microsoft's recommended pattern for script contexts.

## Behaviour changes

- **No functional change**: `window.widgetConfig.label` still contains the label value, correctly decoded, and remains accessible to application code.
- **Timing**: The value is now read from the DOM at script execution time rather than embedded at page-generation time. This has negligible performance impact.
- **Encoding**: HTML attribute encoding (applied by Razor) is the appropriate encoding for this context. The value is automatically decoded when retrieved via `getAttribute()`.
