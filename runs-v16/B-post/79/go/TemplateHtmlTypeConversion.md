## Verdict

exploitable

## Source

`reviewText := r.FormValue("reviewText")` at line 16. Untrusted HTTP form data, attacker-controlled.

## Fix

**Vulnerable code (line 18-23):**
```go
data := struct {
	Body template.HTML
}{
	// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
	Body: template.HTML(reviewText),
}
```

**Fixed code:**
```go
data := struct {
	Body string
}{
	Body: reviewText,
}
```

## Explanation

The vulnerability occurs because `template.HTML()` wraps untrusted input in a type that signals to the template engine "this value is already trusted HTML, do not escape it." This bypasses `html/template`'s automatic context-aware escaping. The fix removes the `template.HTML()` wrapper and changes the struct field type from `template.HTML` to `string`. Since the template already uses `html/template` (imported at line 4), the template engine will now automatically apply HTML entity encoding when rendering the string value into the HTML body context, converting characters like `<`, `>`, and `&` to their safe encoded forms (`&lt;`, `&gt;`, `&amp;`). This prevents injected script tags and event handlers from executing.

## Behaviour changes

none

The fix preserves the sink contract: `reviewTmpl.Execute()` receives a data struct with a `Body` field containing the review text, and renders it into the template in the same location. The only change is that escaping is now applied, which is the intended behaviour. No output is discarded, no implicit defaults change, and error handling remains unchanged.
