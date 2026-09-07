# CWE-78 Remediation: TaintedExecutableName

## Verdict

The vulnerability is real and exploitable. The `tool` parameter is taken directly from untrusted HTTP query input and passed to `exec.Command()` as the executable name without validation. An attacker can supply arbitrary executable paths, including absolute paths to malicious binaries, relative paths with traversal sequences, or shell metacharacters designed to confuse path resolution.

## Source

- **File**: `diagnostics.go`
- **Lines**: 13-14 (source), 35 (sink)
- **Source**: HTTP query parameter `tool` from `r.URL.Query().Get("tool")` (line 13)
- **Sink**: First argument to `exec.Command(tool, "-c", "4", target)` (line 35)
- **Data flow**: User supplies `tool` query parameter → `tool` variable → passed directly to `exec.Command()` as executable name

## Fix

### File: diagnostics.go

```go
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
)

// Allowed diagnostic tools. Maps user-facing tool names to their absolute paths.
var allowedTools = map[string]string{
	"ping":       "/bin/ping",
	"traceroute": "/usr/bin/traceroute",
	"dig":        "/usr/bin/dig",
	"nslookup":   "/usr/bin/nslookup",
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
	// Validate tool against allowlist of known, safe tools
	toolPath, ok := allowedTools[tool]
	if !ok {
		return nil, fmt.Errorf("unsupported diagnostic tool: %s", tool)
	}

	cmd := exec.Command(toolPath, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation

The original code passes the user-supplied `tool` parameter directly to `exec.Command()`, which interprets it as an executable name or path. An attacker can supply arbitrary paths, including `/bin/sh`, `../malicious`, or other system executables.

The fix implements an allowlist pattern: a package-level `allowedTools` map defines the known, safe diagnostic utilities and their absolute paths. Before execution, the user's input is validated against this allowlist in `runDiagnostic()`. Only a match in the map produces a canonical `toolPath` variable; this resolved path is used in `exec.Command()`, not the raw user input.

The use of absolute paths (`/bin/ping`, `/usr/bin/traceroute`, etc.) serves two purposes:
1. It prevents attackers from leveraging a writable `PATH` entry to inject a malicious binary of the same name.
2. It ensures consistent, predictable tool invocation regardless of the process environment.

The fix preserves the original contract: it still returns `CombinedOutput()` from the diagnostic tool and propagates errors to the caller. Invalid tool names now return an error rather than attempting execution, which is appropriate for a constrained endpoint.

## Behaviour changes

- **Valid tools**: Requests with `tool=ping`, `tool=traceroute`, `tool=dig`, or `tool=nslookup` continue to work as before, executing the corresponding absolute path.
- **Invalid tools**: Requests with any other `tool` value now return `HTTP 500` with a diagnostic-failed error message stating "unsupported diagnostic tool", rather than attempting to invoke an arbitrary executable.
- **Tool paths**: Execution now uses absolute, hardcoded paths (`/bin/ping`, `/usr/bin/traceroute`, etc.) instead of resolving tool names through `PATH`.
- **Error contract**: The return signature of `runDiagnostic()` is unchanged; it returns `([]byte, error)`. Invalid tool selections are signalled via the error return, which the handler converts to an HTTP 500 response with an appropriate error message.
- **Security posture**: The endpoint is now restricted to a small, application-defined set of diagnostic utilities. No arbitrary executables can be invoked.
