## Verdict

exploitable (confidence: high)

## Source

`r.FormValue("reviewText")` in `postReviewHandler` (line 16) - attacker-controlled form input from an HTTP POST to `/reviews`.

## Fix

Vulnerable code:

```go
data := struct {
	Body template.HTML
}{
	// SAST FINDING: CWE-79 reported here. Sink is the next statement.
	Body: template.HTML(reviewText),
}

w.Header().Set("Content-Type", "text/html")
reviewTmpl.Execute(w, data)
```

Fixed code:

```go
data := struct {
	Body string
}{
	Body: reviewText,
}

w.Header().Set("Content-Type", "text/html")
reviewTmpl.Execute(w, data)
```

## Explanation

The struct field `Body` was typed `template.HTML`, and `reviewText` was wrapped in that type before being handed to `reviewTmpl.Execute`. `template.HTML` is `html/template`'s explicit "this is already-safe HTML, do not escape" marker - it disables the package's context-aware escaping for that value, so the raw form input is written verbatim into the `<div class="review-body">{{.Body}}</div>` slot. A reviewer submitting `reviewText=<script>...</script>` gets that markup executed in every browser that loads the page. The fix removes the `template.HTML` conversion and changes the field's static type to `string`. `html/template` escapes any pipeline value whose static type is not one of its "safe" wrapper types, so `{{.Body}}` now runs through the package's HTML-body escaper automatically, turning `<`, `>`, `&`, and quotes into inert entities while leaving ordinary text intact. No other part of the handler or template changes, so the fix is a minimal, template-driven closure of the sink rather than a hand-rolled encoder.

## Behaviour changes

- Review text containing HTML markup (e.g. a user typing `<b>great</b>` intending literal angle brackets, or any markup at all) is now rendered as escaped literal text in the page instead of being interpreted as HTML. This is the intended effect of closing the weakness: the review body sink has no legitimate need to accept raw HTML from a form field, and no sanitizer allowlist (e.g. `bluemonday`) is introduced because the field is plain review text, not a rich-text authoring input. If rich-text formatting is actually a product requirement for this field, that requires a separate sanitize-then-`template.HTML` pattern, not a template-level escaping bypass.
- No other behavior changes: response status, `Content-Type` header, template structure, and all other fields/handlers are unchanged.
