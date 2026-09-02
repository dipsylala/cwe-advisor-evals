## Verdict
Real issue. The code allows attackers to define arbitrary XML entities through URL parameters, enabling XXE attacks.

## Source
Line 20 passes untrusted user input (`label`) directly into the XML decoder's Entity map. The `label` parameter originates from `r.URL.Query().Get("noteLabel")`, which is under attacker control.

## Fix
Remove the line that sets decoder.Entity with untrusted input:

```go
decoder := xml.NewDecoder(r.Body)
// REMOVED: decoder.Entity = map[string]string{"noteLabel": label}

var order Order
if err := decoder.Decode(&order); err != nil {
    http.Error(w, "invalid order", http.StatusBadRequest)
    return
}
```

If custom entity expansion is genuinely required, define a static, pre-approved entity map instead of one derived from user input.

## Explanation
The `xml.Decoder.Entity` field controls which custom XML entities the parser will expand. By deriving the entity map from a query parameter, this code allows attackers to inject arbitrary entity definitions. This can be exploited to:
- Define recursive or deeply-nested entities causing entity expansion attacks (DoS)
- Define external entities pointing to local files or SSRF targets
- Redefine internal entity behavior

The safest approach is to not allow custom entity definitions based on user input at all. The XML decoder will handle standard entities and respect defined DOCTYPE declarations appropriately without this field. If specific named entities must be supported, define them as a static allowlist vetted at development time, not derived from runtime user input.
