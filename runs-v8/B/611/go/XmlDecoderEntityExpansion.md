## Verdict

Exploitable

## Source

`r.URL.Query().Get("noteLabel")` (line 16) - attacker-controlled query parameter passed directly to `xml.Decoder.Entity` map without validation or sanitization.

## Fix

**Vulnerable Code (line 20):**
```go
decoder.Entity = map[string]string{"noteLabel": label}
```

**Fixed Code:**
```go
// Line 20 removed - do not populate Entity from untrusted input
```

**Full corrected function:**
```go
func handleOrder(w http.ResponseWriter, r *http.Request) {
	decoder := xml.NewDecoder(r.Body)
	// Entity map is omitted - not needed for basic XML decoding

	var order Order
	if err := decoder.Decode(&order); err != nil {
		http.Error(w, "invalid order", http.StatusBadRequest)
		return
	}

	w.Write([]byte("order accepted: " + order.Item))
}
```

## Explanation

The vulnerability occurs because the code populates `xml.Decoder.Entity` from an untrusted query parameter. The `Entity` field in Go's XML decoder allows custom entity substitution, and when populated from attacker-controlled input, it enables entity injection attacks. The Go-specific guidance explicitly states: "Never populate `xml.Decoder.Entity` from untrusted document content; keep it a small, fixed, application-defined substitution map or omit it entirely." The fix removes the line that populates Entity from the query parameter. The `Entity` field is optional; Go's `xml.Decoder` functions correctly without it. This eliminates the injection point while preserving all intended functionality.

## Behaviour changes

None. The `Entity` map is not required for XML decoding. Removing it has no effect on the decoder's operation - the XML document is still parsed correctly into the `Order` struct using only the standard decoding behavior.
