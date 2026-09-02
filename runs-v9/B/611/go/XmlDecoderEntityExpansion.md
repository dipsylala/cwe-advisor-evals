## Verdict

Exploitable. Confidence: high.

- cwe_id: CWE-611 (Improper Restriction of XML External Entity Reference)
- location: `XmlDecoderEntityExpansion.go`, line 20 (`decoder.Entity = map[string]string{"noteLabel": label}`)

## Source

`label := r.URL.Query().Get("noteLabel")` (line 16) - an attacker-controlled query string parameter, read with no validation or length constraint.

## Fix

Vulnerable code:

```go
func handleOrder(w http.ResponseWriter, r *http.Request) {
	label := r.URL.Query().Get("noteLabel")

	decoder := xml.NewDecoder(r.Body)
	// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
	decoder.Entity = map[string]string{"noteLabel": label}

	var order Order
	if err := decoder.Decode(&order); err != nil {
		http.Error(w, "invalid order", http.StatusBadRequest)
		return
	}

	w.Write([]byte("order accepted: " + order.Item))
}
```

Fixed code:

```go
func handleOrder(w http.ResponseWriter, r *http.Request) {
	decoder := xml.NewDecoder(r.Body)

	var order Order
	if err := decoder.Decode(&order); err != nil {
		http.Error(w, "invalid order", http.StatusBadRequest)
		return
	}

	w.Write([]byte("order accepted: " + order.Item))
}
```

No third-party library change is required; the fix is entirely at the `encoding/xml` `Decoder.Entity` configuration point.

## Explanation

`xml.Decoder.Entity` is a general-entity substitution table: any `&name;` reference the decoder meets in the body is replaced with the corresponding map value before the result is bound into the target struct. This code populated that table's value directly from an unauthenticated query parameter, so a request containing `&noteLabel;` inside, e.g., the `<note>` element would have its parsed content spliced with attacker-chosen text supplied in the same request's query string - including raw XML metacharacters, since substitution happens during parsing, before the struct's field boundaries are enforced. That lets an attacker inject literal markup into the parse tree (altering which fields get populated) or reference the entity repeatedly to amplify a single query value into many bytes of parsed content, an entity-expansion-style resource multiplier. The fix removes the custom `Entity` map entirely rather than trying to sanitize its value, per the Go-specific guidance ("never populate `xml.Decoder.Entity` from untrusted document content; keep it a small, fixed, application-defined substitution map or omit it entirely"): there is no legitimate use of this field in the handler, so omitting it is the correct, minimal fix. With `Entity` unset, `Decoder.Strict` still defaults to `true`, so an `&noteLabel;` (or any other undefined) entity reference now fails XML parsing outright instead of being silently substituted with attacker data - decode errors continue to route through the existing `http.Error(w, "invalid order", http.StatusBadRequest)` path.

## Behaviour changes

None beyond closing the weakness; the `Decode` error-handling path (400 response on any parse failure) is unchanged. The one functional difference is intrinsic to the fix: a request body containing an `&noteLabel;` entity reference previously decoded successfully with attacker-controlled substitution text spliced in, and now fails to decode (falls into the existing 400 "invalid order" branch) because no custom entity table is defined. The now-unused `label` variable was removed since populating the entity map was its only purpose in the function.
