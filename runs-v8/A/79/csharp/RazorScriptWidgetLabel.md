## Verdict

Confirmed XSS vulnerability via unescaped user input in JavaScript context.

## Source

`Model.Label` (from WidgetViewModel) flows directly into a JavaScript string literal without JavaScript-specific escaping.

## Fix

Replace line 7:
```razor
label: "@Html.Raw(Model.Label)",
```

With:
```razor
label: "@Html.Raw(System.Web.HttpUtility.JavaScriptStringEncode(Model.Label))",
```

## Explanation

The vulnerability occurs because `@Html.Raw()` bypasses HTML encoding and outputs the value as-is. When untrusted user input is placed inside a JavaScript string without proper escaping, an attacker can inject a quote character and arbitrary JavaScript code.

For example, if `Model.Label` contains `"; alert('XSS'); //"`, the current code produces:
```javascript
label: ""; alert('XSS'); //"
```

The injected script executes in the browser.

The fix uses `System.Web.HttpUtility.JavaScriptStringEncode()` to escape the value for JavaScript string context. This method escapes special characters like quotes and backslashes that have meaning in JavaScript strings, preventing the injection. The result is then wrapped in `@Html.Raw()` to prevent Razor from applying HTML encoding on top of the JavaScript escaping, since the value is already properly escaped for its context.
