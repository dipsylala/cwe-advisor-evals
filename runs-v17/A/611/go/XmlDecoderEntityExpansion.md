## Verdict
CONFIRMED

## Source
The vulnerability originates at line 16 where untrusted user input is read from the URL query parameter `noteLabel` via `r.URL.Query().Get("noteLabel")`. This untrusted input flows directly to line 20 where it is assigned as an XML entity definition via `decoder.Entity`.

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
	label := r.URL.Query().Get("noteLabel")

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
The vulnerability at line 20 allows an attacker to define arbitrary XML entities by controlling the `noteLabel` query parameter. By injecting specially crafted entity definitions, an attacker can trigger XML External Entity (XXE) attacks, including billion laughs attacks (XML bomb), external entity expansion, and potentially remote code execution depending on the Go version and libxml2 backend.

The fix removes the dangerous line `decoder.Entity = map[string]string{"noteLabel": label}`. This prevents untrusted user input from being used to define XML entities that the decoder will expand. The unused `label` variable is also removed from the function to eliminate dead code. If the `noteLabel` parameter is genuinely needed for the application's functionality, it should be passed to the handler through a separate mechanism (such as a request context or header) that does not involve XML entity expansion, rather than being injected as an entity definition for the XML parser.
