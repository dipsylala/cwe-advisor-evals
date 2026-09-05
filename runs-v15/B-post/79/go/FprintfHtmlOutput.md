## Verdict

EXPLOITABLE. The vulnerability is confirmed: untrusted query parameters are rendered directly into HTML output without context-aware encoding, enabling arbitrary JavaScript injection.

## Source

Untrusted data sources:
- Line 9: `ticketID := r.URL.Query().Get("id")` - HTTP query parameter, attacker-controlled
- Line 10: `customerNote := r.URL.Query().Get("note")` - HTTP query parameter, attacker-controlled

## Fix

Replace `fmt.Fprintf` string concatenation with `html/template`, which applies automatic context-aware HTML escaping to untrusted values:

```go
package main

import (
	"html/template"
	"log"
	"net/http"
)

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	tmpl, err := template.New("ticket").Parse(`<html><body>
<h2>Ticket {{.TicketID}}</h2>
<p>Customer note: {{.CustomerNote}}</p>
</body></html>`)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	data := struct {
		TicketID     string
		CustomerNote string
	}{
		TicketID:     ticketID,
		CustomerNote: customerNote,
	}
	
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("template execution error: %v", err)
	}
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The original code used `fmt.Fprintf` to concatenate untrusted query parameters directly into an HTML response. This is a taint sink: any special HTML characters in the input (such as `<`, `>`, `"`, `'`, `&`) are output verbatim, allowing an attacker to inject script tags or event handlers.

The fix uses Go's `html/template` package, which automatically escapes values based on their context. When a template action like `{{.TicketID}}` appears in HTML body text, the template engine escapes the value—converting `<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`, and quotes as needed. This ensures that user input remains data and cannot be interpreted as code.

The parsed template enforces this escaping at the template-execution layer, so every value bound to the template is safely encoded before rendering. No hand-rolled escaping is needed, and the escaping adapts automatically to the context where each value appears (HTML body, attribute, etc.).

## Behaviour changes

1. **Output encoding**: Untrusted input is now HTML-entity-encoded (e.g., `<script>` becomes `&lt;script&gt;`), preventing script injection.
2. **Error handling**: Template parsing and execution errors are now explicitly handled and logged. Parse errors return a 500 error to the client; execution errors are logged without sending a response.
3. **Response generation**: The response is now generated via template execution rather than sequential `fmt.Fprintf` calls, ensuring all output flows through the template engine's escaping layer.
4. **Special characters preserved**: Legitimate input containing special characters (e.g., "A & B", "5 < 10") now renders correctly, with characters escaped for HTML display but readable to the user.
