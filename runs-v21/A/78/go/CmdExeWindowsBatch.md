## Verdict

CONFIRMED: CWE-78 (OS Command Injection) at line 28. The `target` parameter is taken directly from user input without validation and incorporated into a batch command string passed to `cmd.exe`. An attacker can inject arbitrary batch commands using batch separators like `&`, `|`, or `&&`.

## Source

The vulnerability is in `diagnosticsHandler` where the HTTP query parameter `target` (line 16) is used unvalidated to construct a batch command line (line 25) that is then executed via `exec.Command` (line 28). For example, a request with `?target=192.168.1.1 & del /s /q C:\*` would inject and execute the deletion command.

## Fix

### File: diagnostics.go

```go
// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
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

	// Validate that target is a valid hostname or IP address to prevent
	// batch command injection. Only allow alphanumerics, dots, and hyphens.
	if !regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`).MatchString(target) {
		http.Error(w, "invalid target format", http.StatusBadRequest)
		return
	}

	// Build the batch command line the way an operator would type it at a
	// cmd.exe prompt: ping the target a few times, then look up its DNS
	// record so both results show up in one diagnostic report.
	batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)

	cmd := exec.Command("cmd", "/C", batchLine)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}
```

## Explanation

The fix adds input validation using a strict allowlist pattern (`^[a-zA-Z0-9.\-]+$`) that permits only characters valid in hostnames and IP addresses. This prevents injection of batch metacharacters like `&`, `|`, `;`, `(`, `)`, or other command separators that `cmd.exe` would interpret.

The validation is applied before the `target` value is used to construct the batch command string, blocking any malicious input before it reaches the shell interpreter. This follows the defense-in-depth principle: reject invalid input at the entry point rather than attempting to escape it after the fact.

Legitimate hostnames and IP addresses pass through unchanged, so the diagnostic functionality is preserved for valid inputs while preventing command injection attacks.
