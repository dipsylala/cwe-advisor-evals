## Verdict

exploitable (confidence: high)

CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting'), at `TemplateHtmlTypeConversion.go:22`.

## Source

`r.FormValue("reviewText")` in `postReviewHandler` (line 16) - an attacker-controlled value taken directly from an HTTP form submission, with no validation or sanitization applied before use.

## Fix

Vulnerable code:

```go
data := struct {
    Body template.HTML
}{
    // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    Body: template.HTML(reviewText),
}
```

Fixed code:

```go
data := struct {
    Body string
}{
    Body: reviewText,
}
```

No other lines in the file need to change. `reviewTmpl.Execute(w, data)` and the `{{.Body}}` action in the template stay exactly as written - the fix is entirely in the type carried by the struct field.

## Explanation

The struct field `Body` is declared as `template.HTML`, and the raw form value is cast to that type with `template.HTML(reviewText)` before being handed to `reviewTmpl.Execute`. `html/template` treats a `template.HTML`-typed value as pre-escaped, trusted markup and emits it into the `<div class="review-body">{{.Body}}</div>` context verbatim, so any `<script>`, `<img onerror=...>`, or similar payload in `reviewText` is written into the response byte-for-byte and executes in the victim's browser. Changing the field's type to plain `string` removes the conversion that bypasses escaping: `html/template` now treats `.Body` as untrusted text and applies its context-aware HTML-body escaper (`<`, `>`, `&`, quotes, etc. are all encoded) at execution time, so injected markup is rendered as inert text instead of being parsed as HTML. This is the minimal fix - `reviewText` never needed to be treated as pre-sanitized HTML, since a customer review body has no legitimate need to carry raw markup.

## Behaviour changes

- Review bodies containing HTML markup (intentional or not) now render as literal text (e.g. `<b>great</b>` displays as the literal characters) instead of being interpreted as HTML. This is the direct and required consequence of closing the XSS: the endpoint previously allowed submitters to inject arbitrary markup/script by design of the `template.HTML` cast, and that capability is what the fix removes. If reviewers are meant to submit limited rich-text formatting, that requires sanitizing the input with a library such as `github.com/microcosm-cc/bluemonday` (`UGCPolicy()`) and wrapping only its sanitized output in `template.HTML`, rather than restoring the raw type conversion - no evidence in this file indicates that requirement, so it is out of scope for this fix.
- No other change: return values, response status, headers, control flow, and error handling are all unchanged.
