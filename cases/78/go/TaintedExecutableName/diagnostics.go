package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
)

// DiagnosticsHandler lets an on-call engineer run one of a handful of
// network diagnostic utilities against a target host from the ops
// dashboard, e.g. GET /diagnostics/run?tool=ping&target=10.0.0.5
func DiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	target := r.URL.Query().Get("target")

	if tool == "" || target == "" {
		http.Error(w, "tool and target query parameters are required", http.StatusBadRequest)
		return
	}

	output, err := runDiagnostic(tool, target)
	if err != nil {
		http.Error(w, fmt.Sprintf("diagnostic failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// runDiagnostic shells out to the requested diagnostic utility and
// returns its combined output.
func runDiagnostic(tool, target string) ([]byte, error) {
	// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
