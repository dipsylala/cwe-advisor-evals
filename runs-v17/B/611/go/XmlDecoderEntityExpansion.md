## Verdict

The finding is **CONFIRMED**. Line 20 populates `xml.Decoder.Entity` from untrusted user input (`noteLabel` URL parameter), enabling XXE injection through custom entity definitions.

## Source

- **File**: `XmlDecoderEntityExpansion.go`
- **Line**: 20
- **Vulnerable code**: `decoder.Entity = map[string]string{"noteLabel": label}`
- **Untrusted input**: `label := r.URL.Query().Get("noteLabel")` (line 16)

The attacker controls the entity definition through the URL parameter, which is then made available during XML parsing. An attacker could define a malicious entity (e.g., `<!ENTITY xxe SYSTEM "file:///etc/passwd">`) in the Entity map, leading to file disclosure or SSRF.

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

The vulnerability is eliminated by removing the unsafe `decoder.Entity` assignment entirely. The Go standard library's `encoding/xml` package does not resolve external SYSTEM/PUBLIC entities by default and provides safe parsing without custom entity definitions. Allowing `decoder.Entity` to be populated from untrusted user input violates the core XXE protection principle: "never populate `xml.Decoder.Entity` from untrusted document content."

The fix removes both:
1. The URL parameter extraction (`label := r.URL.Query().Get("noteLabel")`) which is no longer needed
2. The vulnerable Entity assignment that allowed attacker-controlled entity definitions

The `xml.Decoder.Decode()` call on line 23 (now line 21 after removal) proceeds safely without custom entities, parsing the XML document strictly into the Order struct. This is the correct and safest approach for untrusted XML input.

## Behaviour changes

The application no longer allows dynamic entity substitution based on URL parameters. XML documents are now parsed without any custom entity mappings. If the application logic genuinely required dynamic entity substitution, this would need to be redesigned using a trusted value passed through a different, validated mechanism—but allowing untrusted user input to define entities is fundamentally incompatible with XXE protection and should not be supported.
