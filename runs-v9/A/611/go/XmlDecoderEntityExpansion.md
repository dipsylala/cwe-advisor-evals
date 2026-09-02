## Verdict

Confirmed. Line 20 assigns `decoder.Entity` from a request-controlled value before the decoder parses attacker-supplied XML, which lets the request itself decide what a custom XML entity expands to.

## Source

`label := r.URL.Query().Get("noteLabel")` (line 16) — an HTTP query parameter, fully attacker-controlled. It flows unmodified into `decoder.Entity = map[string]string{"noteLabel": label}` (line 20), which configures the `encoding/xml` decoder's entity-substitution table before `decoder.Decode(&order)` (line 23) parses the request body.

## Fix

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
	label := r.URL.Query().Get("noteLabel")

	decoder := xml.NewDecoder(r.Body)
	// decoder.Entity is intentionally left nil. Populating it from request
	// data lets the caller decide what a custom entity expands to; leaving
	// it unset keeps the decoder in its default strict mode, where only the
	// five predefined XML entities (&amp; &lt; &gt; &apos; &quot;) resolve
	// and anything else is rejected as a decode error.

	var order Order
	if err := decoder.Decode(&order); err != nil {
		http.Error(w, "invalid order", http.StatusBadRequest)
		return
	}

	if label != "" {
		order.Note = label + ": " + order.Note
	}

	w.Write([]byte("order accepted: " + order.Item))
}

func main() {
	http.HandleFunc("/order", handleOrder)
	http.ListenAndServe(":8080", nil)
}
```

The `noteLabel` query parameter is no longer wired into the parser at all. If the caller's intent was to let the request annotate the note, that is done as an ordinary string operation after `Decode` returns, on data the decoder already produced under its own strict rules — not by handing the parser a custom entity keyed to attacker input.

## Explanation

Go's `encoding/xml` decoder does not fetch external DTDs or resolve `SYSTEM`/`PUBLIC` entities under any configuration, so it is not exposed to the classic file-disclosure or SSRF form of XXE. The one place its entity handling can be widened is the `Entity` field: by default it is `nil` and the decoder runs in strict mode, accepting only the five entities defined by the XML spec and failing decode on anything else. Setting `Entity` to a map installs additional named entities the parser will substitute inline wherever they appear in the document, and here the map (and therefore what a document-referenced entity resolves to) is built directly from an HTTP query parameter on every request.

That hands the requester control over the parser's substitution table for the request it is itself sending. A crafted body that references the entity many times, combined with a large `noteLabel` value, forces the decoder to repeatedly substitute attacker-sized text — an entity-expansion resource-exhaustion vector — and more generally lets the request inject arbitrary text into whatever the parsed document produces, defeating any assumption that decoded field values only ever come from the document's own literal content. Removing the assignment restores the decoder's default strict entity table, which cannot be influenced by request data, closing both the expansion and the substitution-based injection paths while leaving normal decoding of the `Order` struct unaffected.
