## Verdict

Exploitable. Confidence: high.

- CWE-611 (Improper Restriction of XML External Entity Reference)
- Location: `XmlDecoderEntityExpansion.go`, line 20 (`decoder.Entity = map[string]string{"noteLabel": label}`)

## Source

`label := r.URL.Query().Get("noteLabel")` (line 16) - an attacker-controlled HTTP query parameter, flowing directly into the sink two lines later with no validation or sanitization in between.

## Fix

Vulnerable:

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

Fixed:

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

## Explanation

`encoding/xml.Decoder.Entity` is a substitution map the decoder consults whenever the document contains a general entity reference (`&name;`) that isn't one of the built-in five (`lt`, `gt`, `amp`, `apos`, `quot`) and isn't defined by an internal DTD subset; whatever string sits at `Entity[name]` is spliced into the parsed character data verbatim. The vulnerable code populated that map with a value taken straight from the request's query string, so any submitter could choose what text gets substituted into the parsed order wherever the document referenced `&noteLabel;` - an injection point under attacker control at the XML-parsing layer, which is exactly the pattern this repository's Go CWE-611 guidance calls out as the entity-map-population risk in `encoding/xml` (as distinct from classic file-disclosure/SSRF XXE, which `encoding/xml` does not perform). The fix removes the query parameter and the `Entity` assignment entirely rather than trying to sanitize the value, because there is no legitimate reason for a request-supplied string to define what an XML entity reference expands to; `Order.Note` is already the field the document uses to carry note text, decoded through the struct's typed `xml:"note"` tag. With `Entity` left at its zero value (nil), the decoder only resolves the five predefined entities, closing the injection point.

## Behaviour changes

- `noteLabel` query parameter is no longer read or used. Any caller that depended on `&noteLabel;` references inside the submitted XML being substituted with the query value will now get a decode error (`http.StatusBadRequest`, "invalid order") instead of a substituted value, because an undefined entity reference is a parse error in `encoding/xml`. This is the intended effect of the fix: that substitution was the taint sink.
- No other change. The `Order` struct, response body format, decode error handling, and success path (`order.Item` written back) are unchanged - the sink's existing contract (return the decoded struct or a 400 on error) is preserved.
