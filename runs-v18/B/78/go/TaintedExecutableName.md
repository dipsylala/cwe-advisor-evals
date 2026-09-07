## Verdict
exploitable

## Source
HTTP request query parameter `tool` at line 13 in `DiagnosticsHandler`: `r.URL.Query().Get("tool")`

## Fix

### File: diagnostics.go

```go
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
)

// allowedTools maps tool names to their executable paths
var allowedTools = map[string]string{
	"ping":      "ping",
	"traceroute": "traceroute",
	"nslookup":  "nslookup",
	"dig":       "dig",
}

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
	// Validate tool against allowlist of known diagnostic utilities
	cmdPath, ok := allowedTools[tool]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", tool)
	}
	cmd := exec.Command(cmdPath, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation
The original code passes the untrusted `tool` query parameter directly as the executable name to `exec.Command`, allowing an attacker to execute any program on the system. The fix replaces the tainted value with a map-based allowlist of known diagnostic tools. The `tool` parameter is validated against this allowlist before use, and only the canonical tool path from the map is passed to `exec.Command`. If the requested tool is not in the allowlist, the function returns an error instead of attempting execution. This ensures that only the intended diagnostic utilities can be executed, eliminating the command injection vulnerability while preserving the original function's contract: returning `[]byte` output on success or an error on failure.

## Behaviour changes
The function now returns `fmt.Errorf("unknown tool: %s", tool)` when an unrecognized tool name is provided, whereas the original code would attempt to execute it and return an error only from the OS when the executable could not be found. This is a security-necessary constraint: the new behavior explicitly rejects unknown tools at the application level rather than relying on OS-level failure, making the security enforcement obvious and testable.
