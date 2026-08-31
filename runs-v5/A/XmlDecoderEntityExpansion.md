## Verdict

Confirmed. `handleOrder` builds the `xml.Decoder`'s `Entity` substitution table from an
attacker-controlled query parameter before decoding an attacker-controlled request body. That
lets the same request supply both a custom entity reference and the text it expands to, so the
decoder resolves attacker-chosen entity names to attacker-chosen replacement content instead of
rejecting the unknown reference, which is exactly the entity-substitution weakness CWE-611 covers.

## Source

- Query parameter: `r.URL.Query().Get("noteLabel")` (line 16) - attacker-controlled via the request URL.
- Request body: `r.Body`, fed to `xml.NewDecoder` (line 18) - attacker-controlled XML content, including any `&noteLabel;` reference the attacker chooses to place in it.

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

The `noteLabel` query parameter and the `decoder.Entity` assignment are removed entirely. The
`Order` struct already carries a `Note` field, so if the partner integration needs a caller-
supplied label for the note it should be read from a validated request parameter and combined
with `order.Note` in application code after `Decode` returns, never fed into the decoder's entity
table.

## Explanation

`xml.Decoder.Entity` is a substitution list: any entity reference in the document (`&name;`) whose
name matches a key in the map is replaced with that key's string value during parsing. The zero
value of `Entity` is `nil`, and with it unset the decoder only recognizes the five predefined XML
entities (`lt`, `gt`, `amp`, `apos`, `quot`) and rejects any other entity reference in the input as
an error - that is the safe default.

The vulnerable code overrides that default with `map[string]string{"noteLabel": label}`, where
`label` comes straight from the request's query string with no validation. Because the same
attacker also controls the XML body being decoded, a single request can place `&noteLabel;`
anywhere text content is expected and control both what the entity is named and what it expands
to - for example crafting a body that embeds `&noteLabel;` inside `<note>` while setting
`?noteLabel=` to arbitrary text, causing the decoder to splice attacker-chosen content into a
field the application otherwise treats as parsed, structured output. Because the substitution
value is taken fresh from the request on every call, an attacker can also grow it across repeated
or nested entity references to inflate the decoded output size, the entity-expansion / resource-
exhaustion variant this finding is named for. Building the `Entity` map from any request-derived
value defeats the parser's built-in refusal of unrecognized entities, so the fix is to never
populate `Entity` from untrusted input - leave it unset (or, if a fixed set of custom entities is
genuinely required, hardcode that map as a package-level constant with no request data in it) and
handle caller-supplied labels as ordinary validated input after decoding, not through the XML
entity mechanism.
