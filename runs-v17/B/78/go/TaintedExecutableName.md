## Verdict
exploitable

## Source
Untrusted HTTP query parameter `tool` at line 13 (`r.URL.Query().Get("tool")`), passed through the handler and into `runDiagnostic()` at line 21.

## Fix
The vulnerability is eliminated by validating the `tool` parameter against a strict allowlist of permitted executable names, then passing only the canonical absolute path from the allowlist to `exec.Command()`. This prevents arbitrary executable injection while preserving the intended functionality.

### File: diagnostics.go
```go
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
)

// Allowed diagnostic tools mapped to their canonical executable paths.
// Using absolute paths prevents PATH-based substitution attacks.
var allowedTools = map[string]string{
	"ping":     "/bin/ping",
	"tracert":  "/usr/bin/traceroute",
	"nslookup": "/usr/bin/nslookup",
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

	// Validate tool against allowlist and retrieve canonical path
	toolPath, allowed := allowedTools[tool]
	if !allowed {
		http.Error(w, "tool not allowed", http.StatusBadRequest)
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
	// tool is now an allowlist-validated absolute path, not raw user input
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation
The original code at line 35 passed an untrusted HTTP query parameter `tool` directly to `exec.Command()` as the executable name, allowing an attacker to invoke any program on the system. The fix introduces a map-based allowlist (`allowedTools`) that maps friendly tool names (e.g., "ping") to their canonical absolute paths. After the parameter-validation check, the handler now queries this allowlist: if the user-supplied tool name is not present, the request fails with a 400 error. If it matches an allowlist entry, only the canonical absolute path from the map is passed to `exec.Command()` at line 50, never the original untrusted input. This prevents executable name injection while maintaining the intended behavior of restricting the handler to a controlled set of network diagnostic utilities. The absolute paths also prevent `PATH` environment variable manipulation attacks.

## Behaviour changes
New map-based allowlist added (`allowedTools`) to define permitted executables and their paths. New validation added at lines 29-34 to check the tool against the allowlist and reject unmatched requests with a 400 status. The handler now passes the canonical allowlist-approved path (`toolPath`) to `runDiagnostic()` at line 36 instead of the raw user input. The sink at line 50 now receives a validated absolute path instead of untrusted input. No changes to return values, error handling, output behavior, or command arguments (`-c`, `4`, `target`) — these remain unchanged and consistent with the original contract.

