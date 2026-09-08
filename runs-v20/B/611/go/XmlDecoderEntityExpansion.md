## Verdict

Confirmed. `handleOrder` populates `xml.Decoder.Entity` with a value taken directly from an
unvalidated HTTP query parameter before decoding an untrusted request body. `encoding/xml` does
not resolve external `SYSTEM`/`PUBLIC` entities on its own, but `Decoder.Entity` is the
application's own general-entity substitution table, and handing an attacker any control over its
contents reintroduces exactly the entity-substitution risk `encoding/xml`'s defaults avoid.

## Source

`r.URL.Query().Get("noteLabel")` (line 16) - an attacker-controlled HTTP query parameter, assigned
with no validation into `decoder.Entity["noteLabel"]` at line 20, which `decoder.Decode(&order)`
(line 23) consumes on every subsequent parse.

## Fix

### File: XmlDecoderEntityExpansion.go

```go
package main

import (
	"encoding/xml"
	"net/http"
)

type Order struct {
	XMLName xml.Name `xml:"order"`
	Item    string   `xml:"item"`
	Note    string   `xml:"note"`
}

// handleOrder decodes an XML order submitted by a partner integration.
func handleOrder(w http.ResponseWriter, r *http.Request) {
	decoder := xml.NewDecoder(r.Body)

	var order Order
	if err := decoder.Decode(&order); err != nil {
		http.Error(w, "invalid order", http.StatusBadRequest)
		return
	}

	w.Write([]byte("order accepted: " + order.Item))
}

func main() {
	http.HandleFunc("/order", handleOrder)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

`Order` declares no custom general entities, so `decoder.Entity` served no legitimate purpose here
- it existed only to smuggle the `noteLabel` query value into the parser's substitution table. The
fix removes that assignment entirely rather than sanitizing the value, per the Go-specific
guidance's instruction to never populate `Decoder.Entity` from untrusted input and to omit it when
no fixed, application-defined entity set is required. With `Entity` unset, `encoding/xml` falls
back to its safe default: a document referencing any undefined general entity fails to decode with
an error, which `handleOrder` already turns into a `400 invalid order` response, so no new error
path was added. The now-unused `label` variable and its `r.URL.Query().Get("noteLabel")` read were
removed with it, since nothing else in the function referenced them and leaving an unused local
would not compile. `order.Item` continues to flow to the response exactly as before; no other
argument, return path, or failure behavior of `decoder.Decode` was changed.

## Behaviour changes

- The `noteLabel` query parameter is no longer read or used by `handleOrder`; it had no effect
  other than feeding the removed `Entity` map.
- A submitted document that references an undefined general entity (e.g. `&noteLabel;`) will now
  fail to decode and receive `400 invalid order`, instead of having that entity silently replaced
  with the caller-supplied query value. `Order`'s schema (`item`, `note`) does not declare or
  require such an entity, so this affects only documents that depended on the removed,
  attacker-controllable substitution.
- No change to successful decoding of well-formed `<order>` documents or to the `order.Item`
  response format.
- Verified with `go build` and `go vet` against a scratch copy of the fixed file (Go 1.25.5,
  windows/386): both completed cleanly with no errors or diagnostics.
