package archivelist

import "net/http"

func ArchiveListHandler(runner *ArchiveRunner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		archiveName := r.URL.Query().Get("archive")
		if archiveName == "" {
			http.Error(w, "missing archive", http.StatusBadRequest)
			return
		}

		output, err := runner.ListArchive(r.Context(), archiveName)
		if err != nil {
			http.Error(w, "archive listing failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(output)
	}
}
