package main

import (
	"net/http"
	"text/template"
)

var ticketPage = template.Must(template.New("ticket").Parse(`
	<html>
		<body>
			<h2>Ticket Status</h2>
			<p>Subject: {{.Subject}}</p>
		</body>
	</html>
`))

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")

	data := struct {
		Subject string
	}{
		Subject: subject,
	}

	w.Header().Set("Content-Type", "text/html")
	// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
	ticketPage.Execute(w, data)
}

func main() {
	http.HandleFunc("/ticket/status", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
