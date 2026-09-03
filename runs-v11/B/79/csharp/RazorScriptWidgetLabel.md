## Verdict

exploitable

## Source

`Model.Label` - untrusted input from WidgetViewModel, passed to the view without validation or encoding.

## Fix

**Vulnerable code:**
```razor
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
```razor
<section id="widget-preview" data-label="@Model.Label">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: document.getElementById('widget-preview').getAttribute('data-label'),
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation

The vulnerable code uses `@Html.Raw()` which bypasses Razor's automatic encoding, allowing untrusted data from `Model.Label` to be injected directly into JavaScript source code. Because the value appears inside a JavaScript string literal, an attacker can inject a closing quote and arbitrary JavaScript that executes in the browser, leading to full session compromise or credential theft. The fix moves the label to a data attribute on the DOM element where Razor's automatic HTML encoding protects it, then reads it at runtime via JavaScript. This approach treats the value as data rather than code and follows Microsoft's first recommendation for script contexts.

## Behaviour changes

- Label value is now read from a DOM data attribute at runtime instead of embedded in the script source
- Requires JavaScript execution for the widget configuration to be populated (no impact for modern browsers, but the page gracefully handles no-JS scenarios by simply not setting the config)
- No external dependencies introduced
- Value is protected by Razor's automatic HTML attribute encoding when stored in the data attribute, making `<`, `>`, `"`, and `&` safe

