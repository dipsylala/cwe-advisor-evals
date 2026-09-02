## Verdict

exploitable

## Source

Line 16: `reviewText := r.FormValue("reviewText")` — untrusted user input from HTTP form parameter

## Fix

**Vulnerable code:**
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

The vulnerability stems from wrapping untrusted user input in `template.HTML()` at the sink, which explicitly tells the `html/template` engine to treat the string as safe pre-rendered HTML and bypass context-aware escaping. An attacker can inject malicious HTML tags and JavaScript that execute in the victim's browser. The fix removes the `template.HTML()` wrapper and changes the struct field type from `template.HTML` to `string`, allowing `html/template` to automatically apply HTML entity encoding when rendering `{{.Body}}` in the HTML body context. This ensures that special characters like `<`, `>`, `&`, and quotes are safely escaped and interpreted as data, not executable markup.

## Behaviour changes

Field type changes from `template.HTML` to `string`. No method arguments, return values, or discarded outputs change. The template rendering behavior is preserved—`{{.Body}}` is still rendered in HTML body context by `reviewTmpl.Execute(w, data)`—but now with proper HTML escaping applied by `html/template` instead of bypassed by the `template.HTML()` wrapper.
