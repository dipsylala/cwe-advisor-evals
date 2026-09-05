## Verdict
exploitable

## Source
`Model.Label` property on `WidgetViewModel` - untrusted external input

## Fix
**Vulnerable code:**
```html
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

**Fixed code:**
```html
<section id="widget-preview" data-widget-label="@Model.Label">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: document.getElementById('widget-preview').getAttribute('data-widget-label'),
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation
The vulnerability occurs because `@Html.Raw()` bypasses ASP.NET's auto-encoding and renders the model data directly into a JavaScript context. An attacker controlling `Model.Label` can inject JavaScript by breaking out of the string literal - for example, input like `", alert('XSS'), "x: "` becomes executable code. The fix follows Microsoft's primary recommendation for script contexts: move the untrusted value into an HTML data attribute where Razor's `@variable` syntax applies context-appropriate HTML attribute encoding, then read it from JavaScript at runtime using `getAttribute()`. This ensures the value remains data and never crosses into script source code where encoding is insufficient.

## Behaviour changes
The `window.widgetConfig.label` value is now read from the DOM at script execution time rather than embedded as a string literal. This has no functional impact on legitimate use - the resolved value is identical - but improves debuggability slightly since the attribute is visible in the HTML. The data attribute name `data-widget-label` is added to the section element and can be inspected or referenced elsewhere if needed, but is not otherwise used by the application.
