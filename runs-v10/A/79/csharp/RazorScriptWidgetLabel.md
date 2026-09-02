## Verdict

The vulnerability is confirmed. Line 7 uses `@Html.Raw()` to inject `Model.Label` directly into a JavaScript string without escaping, allowing an attacker to break out of the string and inject arbitrary JavaScript code.

## Source

```csharp
<script>
    window.widgetConfig = {
        label: "@Html.Raw(Model.Label)",
        refreshSeconds: @Model.RefreshSeconds
    };
</script>
```

An attacker controlling `Model.Label` can inject JavaScript by providing input such as `"); alert('XSS'); //`, which would close the string and object, then execute arbitrary code.

## Fix

```csharp
<script>
    window.widgetConfig = {
        label: "@Model.Label",
        refreshSeconds: @Model.RefreshSeconds
    };
</script>
```

Remove the `@Html.Raw()` call. Use the undecorated `@Model.Label` expression, which instructs Razor to apply HTML encoding by default. This escapes characters like quotes and angle brackets that would otherwise break out of the JavaScript string context.

## Explanation

`@Html.Raw()` explicitly disables Razor's automatic HTML encoding, creating an XSS vulnerability when user-controlled data is placed in a script context. Removing it restores the default encoding behavior, which neutralizes the injection by escaping special characters. The encoded value is safe when embedded in a JavaScript string literal because HTML entities like `&#34;` for quotes will not be interpreted as JavaScript syntax—they remain literal characters within the string.

