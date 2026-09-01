## Verdict

Confirmed XSS vulnerability. Untrusted `Model.Label` is rendered into a JavaScript object literal inside a `<script>` block using `@Html.Raw()`, which bypasses all encoding. An attacker can inject a string-literal breakout and arbitrary JavaScript code.

## Source

**File:** Views/Dashboard/Widget.cshtml, line 7

**Code:**
```razor
<script>
    window.widgetConfig = {
        label: "@Html.Raw(Model.Label)",
        refreshSeconds: @Model.RefreshSeconds
    };
</script>
```

**Data Origin:** `Model.Label` is an untrusted string property from `WidgetViewModel`, populated from external input.

**Attack Example:** If `Model.Label` contains `"}; alert('xss'); window.x = {"`, the rendered JavaScript becomes:
```javascript
label: "}; alert('xss'); window.x = {",
```
This breaks the string literal and executes arbitrary code.

## Fix

Move the untrusted value to a data attribute on the HTML element and read it from JavaScript at runtime. This keeps the value out of the script context entirely:

```razor
@model WidgetViewModel

<section id="widget-preview" data-label="@Model.Label" data-refresh-seconds="@Model.RefreshSeconds">
    <h2>@Model.Title</h2>
    <script>
        const section = document.getElementById('widget-preview');
        window.widgetConfig = {
            label: section.getAttribute('data-label'),
            refreshSeconds: parseInt(section.getAttribute('data-refresh-seconds'), 10)
        };
    </script>
</section>
```

**Why this fix:**
- `@Model.Label` in the `data-label` attribute uses Razor's automatic HTML encoding, which is appropriate for HTML attributes
- The JavaScript code reads the value at runtime via `getAttribute()`, which always returns a decoded string
- The untrusted value never appears in script source code, eliminating the injection vector entirely

This is Microsoft's first-recommended approach for passing untrusted data into JavaScript contexts.

## Explanation

The original code used `@Html.Raw()` inside a `<script>` block, rendering untrusted data directly into a JavaScript object literal. Even without `Raw()`, Razor's default HTML encoding would be insufficient—HTML encoding escapes `<`, `>`, and `&`, but a JavaScript string literal needs different escaping rules for characters like quotes, backslashes, and line terminators (U+2028/U+2029). An attacker can break out of the string using `"` or `\`, inject semicolons to end the statement, and execute arbitrary code.

The fix moves the untrusted value out of the script element entirely by storing it in a data attribute. HTML attributes use different encoding rules than script contexts, and Razor's automatic encoding is appropriate there. The JavaScript code then reads the safely-encoded attribute value at runtime using `getAttribute()`, which returns a plain string with no code execution. This preserves the original functionality—the JavaScript still receives the label value—while eliminating the XSS vector.

## Behaviour changes

The JavaScript code now reads `label` and `refreshSeconds` from data attributes at runtime instead of having them interpolated into the script during page rendering.

**Visible changes:** None—the same data reaches `window.widgetConfig` with identical values.

**Security change:** Untrusted input no longer appears in script source, removing the string-literal breakout attack surface.

**Implementation note:** `parseInt(..., 10)` ensures the refresh-seconds value is parsed as a base-10 integer, matching the original number literal's behaviour.
