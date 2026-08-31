## Verdict

Confirmed. `reviewText`, taken directly from the request via `r.FormValue("reviewText")`, is converted to `template.HTML` before being rendered into the page. `html/template` treats a `template.HTML` value as pre-sanitized, trusted markup and emits it into the response verbatim, bypassing the package's normal contextual autoescaping. Any HTML or `<script>` content an attacker submits as `reviewText` is rendered and executed in the browser of anyone who views that review, giving a classic stored cross-site scripting vulnerability.

## Source

`reviewText := r.FormValue("reviewText")` in `postReviewHandler` (line 16) — untrusted, attacker-controlled HTTP form input with no validation or sanitization applied before use.

## Fix

```go
func postReviewHandler(w http.ResponseWriter, r *http.Request) {
	reviewText := r.FormValue("reviewText")

	data := struct {
		Body string
	}{
		Body: reviewText,
	}

	w.Header().Set("Content-Type", "text/html")
	reviewTmpl.Execute(w, data)
}
```

The only change needed is the field's type: `Body template.HTML` becomes `Body string`, and the assignment drops the `template.HTML(...)` conversion, passing `reviewText` through as a plain string. The template itself (`{{.Body}}` inside an HTML element body) does not need to change — `html/template` will now apply its default HTML-context escaping to the value automatically.

## Explanation

`html/template` is contextually autoescaping by default: a plain `string` piped into `{{.Body}}` inside an HTML element body is HTML-escaped, turning `<`, `>`, `&`, `"`, and `'` into their entity equivalents so any markup or script tags the user submits are rendered as inert text rather than executed. The `template.HTML` type exists specifically to opt individual values *out* of that escaping — it is meant for markup the application itself generated or that has already been through a trusted sanitizer, never for raw request input. Converting request-derived data to `template.HTML` is the injection point here: it tells the template engine "trust this string as safe markup," which is false for anything read straight from a form field.

Removing the `template.HTML` conversion restores the default escaping behavior and closes the vulnerability with no other code changes required. If the application has a genuine need to allow a restricted subset of HTML formatting in reviews (e.g., bold or line breaks), that requires running the input through a dedicated HTML sanitizer library that allowlists safe tags/attributes and strips everything else, with the sanitized output stored/rendered as `template.HTML`, rather than trusting raw form data directly. For plain-text review content, converting the field back to `string` is sufficient and preferred.
