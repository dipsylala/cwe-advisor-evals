## Verdict
The finding is valid. User-supplied input from `customerNote` is written directly to the HTTP response without escaping, allowing JavaScript injection.

## Source
Line 10: `customerNote := r.URL.Query().Get("note")` retrieves untrusted input from the query parameter.

## Fix
Import the `html` package and escape the `customerNote` before writing it to the response:

```go
package main

import (
	"fmt"
	"html"
	"net/http"
)

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", html.EscapeString(ticketID))
	fmt.Fprintf(w, "<p>Customer note: %s</p>", html.EscapeString(customerNote))
	fmt.Fprintf(w, "</body></html>")
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation
The fix applies `html.EscapeString()` to both `ticketID` and `customerNote` before including them in the HTML output. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting them as markup or script code. User input is now treated as content rather than code.
