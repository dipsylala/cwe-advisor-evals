## Verdict

Exploitable. Untrusted user input from the URL query parameter is directly injected into the XML decoder's Entity map, allowing an attacker to define arbitrary XML entities that could be exploited during parsing.

## Source

Line 16: `label := r.URL.Query().Get("noteLabel")` — untrusted user input from URL query parameter.

## Fix

**Vulnerable code (line 20):**
```go
decoder := xml.NewDecoder(r.Body)
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
decoder.Entity = map[string]string{"noteLabel": label}

var order Order
if err := decoder.Decode(&order); err != nil {
	http.Error(w, "invalid order", http.StatusBadRequest)
	return
}
```

**Fixed code:**
```go
decoder := xml.NewDecoder(r.Body)

var order Order
if err := decoder.Decode(&order); err != nil {
	http.Error(w, "invalid order", http.StatusBadRequest)
	return
}
```

## Explanation

The vulnerability is eliminated by removing the line that populates `xml.Decoder.Entity` from untrusted user input. According to CWE-611 Go guidance, the Entity map must never be populated from untrusted document content or user input; it should be kept as a small, fixed, application-defined substitution map or omitted entirely. The XML decoder in Go's `encoding/xml` package does not resolve external entities by default, so removing the unsafe Entity assignment closes this vulnerability. If the `noteLabel` value is needed in the application, it should be passed through a different mechanism (such as a request context or separate handler parameter) rather than injected into XML entity definitions.

## Behaviour changes

None. The decoder is used identically; only the unsafe Entity map injection is removed. The decoder will process the XML input without expanding custom entities, which is the secure default behaviour for Go's `encoding/xml`.
