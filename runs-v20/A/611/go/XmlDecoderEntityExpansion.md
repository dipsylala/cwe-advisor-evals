## Verdict

Confirmed. `handleOrder` populates `xml.Decoder.Entity` with a value taken directly from the request query string, then decodes an attacker-controlled request body against that decoder. This allows a caller to define their own general entity (e.g. via `&noteLabel;`, or via entities declared in the document's own `DOCTYPE` internal subset) whose expansion text is influenced by request data, letting a crafted payload trigger entity-expansion (billion-laughs style) resource exhaustion during `decoder.Decode`.

## Source

- `label := r.URL.Query().Get("noteLabel")` - attacker-controlled HTTP query parameter.
- `r.Body` - attacker-controlled HTTP request body, parsed by the same decoder.

Both reach the sink at `decoder.Entity = map[string]string{"noteLabel": label}` followed by `decoder.Decode(&order)`.

## Fix

### File: XmlDecoderEntityExpansion.go

```go
package main

import (
	"encoding/xml"
	"io"
	"net/http"
)

type Order struct {
	XMLName xml.Name `xml:"order"`
	Item    string   `xml:"item"`
	Note    string   `xml:"note"`
}

// handleOrder decodes an XML order submitted by a partner integration.
func handleOrder(w http.ResponseWriter, r *http.Request) {
	// Bound how much the decoder will ever read, so a crafted payload that
	// tries to force excessive entity/element expansion cannot consume
	// unbounded memory or CPU regardless of how the document is structured.
	body := io.LimitReader(r.Body, 1<<20) // 1 MiB cap

	decoder := xml.NewDecoder(body)
	// decoder.Entity is intentionally left nil. Only XML's five built-in
	// entities (lt, gt, amp, apos, quot) are resolved; no caller-influenced
	// or request-derived entity mapping is registered, which is what let a
	// submitted document define and expand its own entities.

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

The vulnerable line merged a request-supplied string into the decoder's entity table before parsing an equally attacker-controlled body. `encoding/xml.Decoder.Entity` is meant only for a fixed, developer-defined set of non-standard entity substitutions; it is never appropriate to seed it from request data, because doing so gives the caller a say in how their own document's entities resolve, opening the door to entity-expansion payloads (deeply self-referential or repeated entities) that inflate parsing cost far beyond the size of the wire payload - the same class of resource-exhaustion issue XXE-adjacent CVEs in `encoding/xml` have targeted.

The fix removes the request-derived entity map entirely rather than trying to sanitize it - there is no legitimate reason for a client to influence entity resolution here, and the `Note` field the code actually needs is already populated from the `<note>` element by normal decoding, with no reliance on the `noteLabel` entity. Leaving `Entity` nil restricts resolution to XML's five built-in entities, which are fixed strings and not attacker-influenced.

As defense in depth, the body is wrapped in `io.LimitReader` before it reaches the decoder. This bounds the total bytes the decoder will ever process, so even a pathological but otherwise well-formed document is capped in the resources it can consume, independent of the entity-table fix above.
