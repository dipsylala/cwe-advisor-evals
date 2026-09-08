## Verdict

Confirmed. `Widget.cshtml` line 7 writes `Model.Label` into a `<script>` block through `@Html.Raw()`, inside a double-quoted JavaScript string literal. `Html.Raw()` suppresses Razor's encoding entirely, and even Razor's default `@variable` encoding would not have helped here since it applies HTML-attribute encoding, not JavaScript-string encoding - a `<script>` element is raw text, so HTML entities are never decoded by the browser and the value would still reach the JS parser un-escaped. An attacker-controlled `Label` containing a `"` followed by `,malicious:1};alert(document.cookie);//` (or any payload breaking out of the string literal) executes as script in the victim's browser.

## Source

`WidgetViewModel.Label` (`WidgetViewModel.cs` line 6) is a plain, unvalidated `string` property with no encoding applied anywhere in the two files that make up this case. It flows directly and unmodified into `Widget.cshtml` line 7. The case does not include the code that populates `WidgetViewModel`, so per the autonomous-mode assumption rule, `Label` is treated as attacker-influenced (e.g. a user-supplied widget name or dashboard label) since nothing in the visible chain constrains or validates it.

## Fix

### File: Views/Dashboard/Widget.cshtml
```cshtml
@model WidgetViewModel

<section id="widget-preview" data-label="@Model.Label">
    <h2>@Model.Title</h2>
    <script>
        window.widgetConfig = {
            label: document.getElementById("widget-preview").dataset.label,
            refreshSeconds: @Model.RefreshSeconds
        };
    </script>
</section>
```

## Explanation

This applies the C# guidance's first-choice remediation for script contexts: keep the untrusted value out of the script body entirely by placing it in a `data-*` attribute and reading it back at runtime with the DOM API, rather than trying to escape it correctly for JavaScript-string-literal position. `data-label="@Model.Label"` renders in an HTML attribute context, where Razor's built-in `@variable` encoding is the encoding it was designed for - `"`, `<`, `>`, and `&` in `Label` are all turned into HTML entities, so the value cannot terminate the attribute early. The browser decodes those entities back to the original text only when exposing the attribute through `dataset.label`, which yields a plain JavaScript string value (an object-property read), never a fragment of source that gets parsed as code - so a quote or backslash in `Label` can no longer break out of a string literal or inject a new statement. `RefreshSeconds` is an `int` and was already emitted safely by Razor; it is left untouched. `Html.Raw()` is removed, closing the sink.

## Behaviour changes

None from the page's observable behavior: `window.widgetConfig.label` still ends up holding exactly the text in `Model.Label` (HTML-entity round-tripping via `dataset` is lossless), and `refreshSeconds` is unchanged. The only structural change is that `#widget-preview` now carries a `data-label` attribute and the config object is populated by a short runtime read instead of being inlined literally, which requires `document.getElementById("widget-preview")` to resolve at the point the `<script>` tag runs (true here, since the section markup precedes it in the same element).

Manual review only: no C# checker was run against this snippet, since compiling a Razor view requires scaffolding a full ASP.NET Core project the case does not provide. `document.getElementById` and `HTMLElement.dataset` are standard, long-supported browser APIs and were checked by hand against MDN's documented behavior; the Razor `@Model.Label` / `@Model.RefreshSeconds` syntax and the `data-label` attribute are unchanged from patterns already present in the original file.
