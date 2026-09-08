## Verdict

The CWE-611 XXE injection finding is valid and exploitable. User-controlled input from the URL query parameter `noteLabel` is directly inserted into the XML decoder's `Entity` map, allowing an attacker to inject arbitrary entity definitions that will be substituted during XML parsing.

## Source

The vulnerability originates at line 16 with untrusted user input:
```
label := r.URL.Query().Get("noteLabel")
```

This value flows directly to the vulnerable sink at line 20:
```
decoder.Entity = map[string]string{"noteLabel": label}
```

The attacker-controlled entity definition is then used by the decoder when parsing the request body XML at line 23, allowing entity injection attacks.

## Fix

The fix removes the Entity population from untrusted user input. The `Entity` field must only contain fixed, application-defined substitutions that do not originate from user input.

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

The vulnerability existed because user-controlled input from the URL query parameter was being inserted into the XML decoder's `Entity` map. This allowed an attacker to define arbitrary XML entities that would be substituted during the parsing of the request body XML. According to CWE-611 guidance for Go: "Never populate `xml.Decoder.Entity` from untrusted document content; keep it a small, fixed, application-defined substitution map or omit it entirely."

The fix removes both the untrusted input retrieval and the Entity map population. Go's standard `encoding/xml` package does not resolve external SYSTEM/PUBLIC entities by default, so the decoder is safe without explicit entity definitions. The application now:
1. Accepts XML order input without custom entity substitutions
2. Decodes it into the Order struct with explicit type safety via the XML struct tags
3. Eliminates the XXE injection vector by removing the untrusted entity control

This aligns with the Go-specific principle that the application should control XML parsing behavior entirely, not allow users to inject custom entity definitions.

## Behaviour changes

- **Removed**: The `noteLabel` URL query parameter is no longer accepted or processed.
- **Impact**: Any callers passing the `noteLabel` parameter will find it ignored. If the entity substitution was functionally required, this represents a breaking change that requires the upstream integration to be updated to pass the entity value through the XML document itself (as an element or attribute) rather than through the URL, if needed.
- **Security impact**: Positive - eliminates the XXE injection vulnerability while maintaining the core functionality of accepting and parsing XML orders.
