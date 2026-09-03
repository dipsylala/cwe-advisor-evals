## Verdict

The vulnerability is confirmed. Line 20 populates `xml.Decoder.Entity` with a map containing untrusted input from the URL query parameter (`noteLabel`), which violates the core CWE-611 remediation principle for Go. While Go's standard `encoding/xml` does not resolve external SYSTEM/PUBLIC entities by default, populating the Entity map from untrusted input creates a XXE injection vector.

## Source

The vulnerable pattern is:
```go
label := r.URL.Query().Get("noteLabel")
decoder := xml.NewDecoder(r.Body)
decoder.Entity = map[string]string{"noteLabel": label}
```

The attacker can supply a malicious `noteLabel` value in the query string that becomes part of the entity substitution map applied during XML decoding.

## Fix

Remove the Entity population entirely. The fixed code is:

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
	// Do not populate xml.Decoder.Entity from untrusted input
	// If fixed entity substitution is required, define it as a constant map unrelated to user input

	limitedBody := io.LimitReader(r.Body, 10*1024*1024) // 10 MB limit
	decoder := xml.NewDecoder(limitedBody)

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

The remediation follows the Go CWE-611 guidance principle: "Never populate `xml.Decoder.Entity` from untrusted document content; keep it a small, fixed, application-defined substitution map or omit it entirely."

The fix removes the line that constructs an Entity map from the URL query parameter. Since the entity substitution is not required for this use case (the XML structure defines `item` and `note` fields directly), the Entity map is simply omitted.

Defense-in-depth hardening is added via `io.LimitReader`, which bounds the XML input size to prevent denial-of-service attacks through deeply-nested or extremely large documents. This addresses the secondary XXE risk in Go, which involves stack exhaustion from deeply nested XML structures rather than external entity expansion.

## Behaviour changes

- Removal of the Entity substitution map prevents attacker-controlled entity expansion during XML decoding
- Input size is now limited to 10 MB, preventing DoS attacks through oversized payloads
- The XML decoder still uses Go's safe default parser settings (no external entity resolution, no DTD processing)
- The handler continues to decode XML into the Order struct and returns the same response format
- The only behavioral change from a legitimate caller's perspective is that the URL query parameter `noteLabel` is no longer substituted into the XML decoding context; if this parameter was previously used to inject entity substitutions into the XML, that functionality is removed as a security fix
