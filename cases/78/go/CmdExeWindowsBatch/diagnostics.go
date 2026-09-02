// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
)

// diagnosticsHandler runs a Windows diagnostic command chosen by the
// caller and returns its combined output. It is registered at
// /internal/diagnostics and is intended for use from the ops dashboard.
func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Build the batch command line the way an operator would type it at a
	// cmd.exe prompt: ping the target a few times, then look up its DNS
	// record so both results show up in one diagnostic report.
	batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)

	// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
	cmd := exec.Command("cmd", "/C", batchLine)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}
