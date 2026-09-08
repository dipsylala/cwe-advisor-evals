## Verdict

Exploitable

## Source

`Model.Label` in WidgetViewModel (untrusted user input)

## Fix

### File: Views/Dashboard/Widget.cshtml

```csharp
@using System.Text.Encodings.Web
@model WidgetViewModel

<section id="widget-preview">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: "@JavaScriptEncoder.Default.Encode(Model.Label)",
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation

The vulnerability occurs on line 7 where untrusted user input (`Model.Label`) is rendered directly into a JavaScript string literal inside a `<script>` block using `@Html.Raw()`, which bypasses Razor's automatic encoding. An attacker can inject a value like `", malicious: "` to break out of the string context and execute arbitrary JavaScript.

The fix replaces `@Html.Raw(Model.Label)` with `@JavaScriptEncoder.Default.Encode(Model.Label)`, which is the appropriate context-specific encoder from `System.Text.Encodings.Web`. This encoder escapes quotes, backslashes, line terminators, and other special characters that could break out of a JavaScript string literal, preventing injection while preserving legitimate content containing characters like `<`, `&`, and quotes.

## Behaviour changes

None. The functionality is preserved—the label value is still assigned to the JavaScript object and remains readable. The only difference is that special characters are escaped in the output, which is required for security and does not affect the application's behavior since JavaScript engines transparently decode the escaped sequences back to their original characters when the string is used.
