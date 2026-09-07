## Verdict
CONFIRMED

## Source
The `tool` parameter originates from untrusted user input (HTTP query parameter at line 13) and flows directly to `exec.Command()` at line 35 without validation. An attacker can supply arbitrary executable names or paths, enabling OS command injection.

## Fix

### File: diagnostics.go

```go
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

// allowedTools is a whitelist of permitted diagnostic utilities.
var allowedTools = map[string]bool{
	"ping":       true,
	"traceroute": true,
	"nslookup":   true,
	"dig":        true,
}

// runDiagnostic shells out to the requested diagnostic utility and
// returns its combined output.
func runDiagnostic(tool, target string) ([]byte, error) {
	// Validate that the requested tool is in the allowlist.
	if !allowedTools[tool] {
		return nil, fmt.Errorf("tool %q is not permitted", tool)
	}

	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation
The vulnerability exists because `tool` is passed directly to `exec.Command()` without validation. An attacker can request any executable name, including paths like `/bin/sh` or malicious commands.

The fix implements a whitelist of permitted diagnostic utilities (`ping`, `traceroute`, `nslookup`, `dig`) and validates the user input against this list before execution. If an unpermitted tool is requested, the function returns an error instead of executing it. This approach restricts the execution to the intended set of diagnostic tools, preventing arbitrary command execution.
