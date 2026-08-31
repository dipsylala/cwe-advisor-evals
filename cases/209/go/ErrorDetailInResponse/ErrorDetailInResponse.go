package main

import (
	"fmt"
	"net/http"
	"os"
)

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	f, err := os.Open("/var/data/reports/" + filename)
	if err != nil {
		wrapped := fmt.Errorf("could not open report %q: %w", filename, err)
		// SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
		http.Error(w, wrapped.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "serving report %s", filename)
}

func main() {
	http.HandleFunc("/download", downloadHandler)
	http.ListenAndServe(":8080", nil)
}
