## Verdict

Exploitable. The code populates `xml.Decoder.Entity` with untrusted input from an HTTP query parameter, allowing an attacker to inject arbitrary entity definitions that are expanded during XML parsing. This violates CWE-611 guidance that explicitly forbids populating the Entity map from untrusted sources.

## Source

Line 16: `label := r.URL.Query().Get("noteLabel")` — untrusted HTTP query parameter supplied by the client.

## Fix

Remove line 20 entirely. The Entity field should not be populated from untrusted input.

**Vulnerable code (lines 15-26):**
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

**Fixed code (lines 15-26):**
```go
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
```

## Explanation

The vulnerable code populates `xml.Decoder.Entity` with an entity definition derived from untrusted HTTP query parameter input. Go's `encoding/xml` package does not resolve external entities by default, but custom entity definitions added via the `Entity` field are expanded during decoding. By allowing an attacker to control entity definitions, this opens an XXE vector: an attacker can craft XML input that references a controlled entity to inject arbitrary values into the decoded struct, potentially bypassing validation or modifying application behavior.

The fix removes the line that populates `Entity` from untrusted input. According to CWE-611 Go-specific guidance, the Entity field should only be a "small, fixed, application-defined substitution map or omit it entirely." Untrusted input must never populate this field. By removing the assignment, the decoder operates with an empty Entity map, so only entity references that already exist in the XML input are rejected or treated as unresolved, preventing injected entity expansion.

## Behaviour changes

- **Before**: A client can supply arbitrary entity substitutions via the `noteLabel` query parameter, which are applied during XML parsing.
- **After**: The `noteLabel` query parameter is read but not used to populate the Entity map. The decoder will not expand any custom entities defined via the query parameter, and any entity references in the XML input that are not in the default map will be treated as unresolved.
- **Side effects**: Legitimate use cases that rely on runtime-controlled entity substitution via URL parameters will no longer work. If entity substitution is genuinely required, move the Entity definitions to an application-controlled, hardcoded map that does not include any untrusted input. The `noteLabel` value can still be passed through the XML or query context if needed for non-entity purposes, using the decoded struct fields instead.
