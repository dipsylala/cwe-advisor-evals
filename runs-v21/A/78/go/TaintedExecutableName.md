## Verdict
Confirmed CWE-78: OS Command Injection. The `tool` parameter originates from untrusted user input (HTTP query string at line 13) and is used directly as the executable name in `exec.Command()` at line 35 without validation, allowing an attacker to execute arbitrary commands.

## Source
The vulnerability originates at line 13 where `tool := r.URL.Query().Get("tool")` reads an untrusted query parameter. This value flows directly to line 35 in `exec.Command(tool, "-c", "4", target)`, which becomes the executable name. An attacker can supply arbitrary strings as the tool name, causing execution of unintended programs.

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

	// Whitelist allowed diagnostic tools to prevent command injection
	allowedTools := map[string]string{
		"ping":     "ping",
		"tracert":  "tracert",
		"nslookup": "nslookup",
	}

	toolPath, ok := allowedTools[tool]
	if !ok {
		http.Error(w, "tool not in allowed list", http.StatusBadRequest)
		return
	}

	output, err := runDiagnostic(toolPath, target)
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
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation
The remediation applies a strict whitelist approach: before passing `tool` to `exec.Command()`, the handler validates it against an explicit map of allowed diagnostic tools. Only recognized tool names are permitted; any other input triggers a 400 Bad Request response. This prevents an attacker from injecting arbitrary executable names or path-based references. The `runDiagnostic()` function continues to receive only hardcoded tool names from the allowlist, eliminating the command injection vector at line 35.
