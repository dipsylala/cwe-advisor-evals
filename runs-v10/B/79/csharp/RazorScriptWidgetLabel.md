## Verdict

The vulnerability is confirmed. Line 7 uses `@Html.Raw(Model.Label)` to insert untrusted data directly into a JavaScript string context without encoding, allowing XSS injection.

## Source

`Model.Label` (WidgetViewModel.cs, line 6) - user-controlled string property passed to the view.

## Fix

Replace the direct JavaScript inline approach with a data attribute and DOM read, following the primary remediation pattern from CWE-79/csharp guidance.

**Vulnerable code:**
```razor
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

**Fixed code:**
```razor
@model WidgetViewModel

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

The fix moves `Model.Label` from a JavaScript string context to an HTML data attribute, then retrieves it at runtime via DOM API. This eliminates the injection vector:

- The `@Model.Label` in the attribute uses Razor's automatic HTML encoding (encoding quotes, angle brackets, and ampersands), which is safe for HTML attributes but would be incomplete for JavaScript strings
- JavaScript reads the decoded value via `getAttribute()`, keeping the string entirely outside JavaScript source code
- No `@Html.Raw()` bypass is used

This follows the CWE-79/csharp guidance's primary recommendation: "put the value in a data attribute on an element and read it from JavaScript at runtime, so the value never crosses into script source."

## Behaviour changes

- `Model.Label` is now read from the DOM at script execution time rather than embedded at template render time
- If `Model.Label` changes after the page loads, the in-memory `window.widgetConfig.label` retains its initial value (it is not reactive)
- The `refreshSeconds` value remains inline because it is an integer; only string data needs protection from JavaScript injection
