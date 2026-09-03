## Verdict

**Vulnerable** — The code allows user-supplied query parameters to define custom XML entities on the decoder, creating a vector for entity expansion attacks and XML External Entity (XXE) exploitation.

## Source

```go
decoder := xml.NewDecoder(r.Body)
decoder.Entity = map[string]string{"noteLabel": label}
```

The vulnerable pattern: `decoder.Entity` is assigned a map containing user input from `r.URL.Query().Get("noteLabel")`. This permits an attacker to inject custom entity definitions that can be used in the XML payload to cause denial of service via entity expansion or to reference external resources.

## Fix

Remove the unsafe entity assignment entirely:

```go
decoder := xml.NewDecoder(r.Body)
// Do not assign decoder.Entity from user input
var order Order
if err := decoder.Decode(&order); err != nil {
	http.Error(w, "invalid order", http.StatusBadRequest)
	return
}
```

The `xml.Decoder` in Go's standard library defaults to safe behavior: it does not expand external entities and rejects entity references that would cause expansion loops. Do not override this safe default with user-controlled entity definitions.

## Explanation

XML entity expansion attacks (such as the "billion laughs" or "quadratic blowup" attack) exploit custom entity definitions to consume memory and CPU, causing denial of service. Permitting user input to define arbitrary entities circumvents the language's built-in protections.

The fix removes the line that maps `decoder.Entity` to attacker-controlled input. If the integration genuinely requires predefined entity substitutions, they must be hardcoded from a trusted configuration, never from user input (query parameters, request headers, or body content). The default decoder behavior in Go is to reject entity references that would cause expansion, which is the correct defensive posture.
