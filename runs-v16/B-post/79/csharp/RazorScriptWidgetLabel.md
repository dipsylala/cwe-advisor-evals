## Verdict

exploitable

## Source

`Model.Label` property in `WidgetViewModel`, passed from untrusted external source to the view.

## Fix

**Vulnerable code (line 7):**
```razor
label: "@Html.Raw(Model.Label)",
```

**Fixed code:**
```razor
@model WidgetViewModel

<section id="widget-preview" data-label="@Model.Label" data-refresh-seconds="@Model.RefreshSeconds">
    <h2>@Model.Title</h2>
    <script>
        const section = document.getElementById('widget-preview');
        window.widgetConfig = {
            label: section.dataset.label,
            refreshSeconds: parseInt(section.dataset.refreshSeconds, 10)
        };
    </script>
</section>
```

## Explanation

The vulnerability occurs at the sink `@Html.Raw(Model.Label)` on line 7 of Widget.cshtml, where untrusted data is placed directly into JavaScript source code within a `<script>` block without encoding. The `@Html.Raw()` method bypasses Razor's automatic HTML encoding, allowing an attacker to inject a string that breaks out of the JavaScript string literal and executes arbitrary code—for example, injecting `", refreshSeconds: 0}; alert('XSS'); window.widgetConfig = {label: "` would terminate the current string, inject an alert statement, and begin a new object literal.

The fix applies Microsoft's first recommendation for data in JavaScript contexts: moving the value to an HTML data attribute and reading it from JavaScript at runtime. This approach eliminates the vulnerability because the value never enters JavaScript source code. Razor automatically HTML-encodes the attribute value `@Model.Label` when placed in the HTML context, and the JavaScript `dataset.label` property reads the decoded but safe value, which is treated as data rather than executable code. The `RefreshSeconds` integer is similarly protected by moving it to a data attribute and parsing it in JavaScript.

## Behaviour changes

1. **Data extraction timing**: The original code embedded values directly into the script block at parse time. The fixed code reads values from the DOM after the element is rendered, adding a small runtime overhead (negligible for typical widget labels).
2. **RefreshSeconds casting**: The original code placed an integer directly into JavaScript as `@Model.RefreshSeconds`. The fixed code reads it as a string from the data attribute and explicitly parses it with `parseInt(..., 10)`, ensuring correct type conversion and making the radix explicit for maintainability.
3. **Attribute references**: The fixed code assumes JavaScript is allowed to run after the DOM is parsed. If a Content Security Policy restricts inline scripts, the `<script>` block itself must be allowlisted or a nonce added, but this is independent of the XSS fix and a separate policy concern.

All other behavior—the title rendering, the structure of `window.widgetConfig`, and the values passed to consumers—remains identical.
