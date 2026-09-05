## Verdict

Exploitable. The `Model.Label` property is untrusted user input passed directly into a JavaScript string context using `@Html.Raw()`, which bypasses Razor's auto-encoding. An attacker can inject quotes and newlines to break out of the string and execute arbitrary JavaScript.

## Source

`WidgetViewModel.Label` - a string property from the model, treated as untrusted user input and passed to the view.

## Fix

**Vulnerable code (line 7):**
```razor
@section id="widget-preview">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: "@Html.Raw(Model.Label)",
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

**Fixed code:**
```razor
@model WidgetViewModel

<section id="widget-preview">
    <h2>@Model.Title</h2>
    <div id="widget-config" data-label="@Model.Label" data-refresh-seconds="@Model.RefreshSeconds"></div>
    <script>
        var configElement = document.getElementById('widget-config');
        window.widgetConfig = {
            label: configElement.getAttribute('data-label'),
            refreshSeconds: parseInt(configElement.getAttribute('data-refresh-seconds'), 10)
        };
    </script>
</section>
```

## Explanation

The fix moves the untrusted value from a JavaScript string context into a data attribute on a DOM element. In the data attribute, Razor's automatic HTML encoding protects the value—it encodes quotes and special characters as HTML entities. The JavaScript then reads the value from the attribute at runtime using `getAttribute()`, which automatically decodes the HTML entities back to the original string, preventing injection. This is Microsoft's recommended pattern for embedding untrusted data in script contexts: keep the value in the HTML layer where context-aware encoding applies, and read it from JavaScript rather than embedding it in script source. The `RefreshSeconds` value is similarly moved to a data attribute and parsed as an integer at runtime, ensuring the original number is never placed directly into JavaScript.

## Behaviour changes

1. **DOM structure**: A new `<div id="widget-config">` element is added to hold the data attributes. It carries no visual styling and does not affect layout or rendering.
2. **Runtime data retrieval**: `window.widgetConfig.label` and `window.widgetConfig.refreshSeconds` are now populated from the DOM at script execution time rather than embedded in the script source. This preserves functionality while moving the value through an encoding boundary.
3. **Integer parsing**: `@Model.RefreshSeconds` is now read as a string from the data attribute and explicitly parsed with `parseInt(..., 10)` to ensure it is a number. The previous code output the number directly in script; the fix achieves the same result via the data attribute, with explicit radix specification for safety.
4. **No change to output contract**: The `window.widgetConfig` object still contains the same two properties with the same final values; the mechanism by which they are populated is the only change.
