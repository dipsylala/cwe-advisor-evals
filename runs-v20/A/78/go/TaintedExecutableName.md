## Verdict

Confirmed. `runDiagnostic` passes the caller-controlled `tool` query parameter directly as the executable name to `exec.Command`, letting a request choose which binary on the host gets executed rather than merely influencing that binary's arguments.

## Source

`r.URL.Query().Get("tool")` in `DiagnosticsHandler` (diagnostics.go line 13), passed unchanged into `runDiagnostic(tool, target)` (line 21) and then into `exec.Command(tool, "-c", "4", target)` (line 35).

## Fix

### File: diagnostics.go
```go
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
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

// allowedDiagnostics maps the caller-supplied "tool" name to the fixed,
// absolute path of the diagnostic utility it may invoke. Only tools listed
// here can ever be executed, regardless of what the "tool" query parameter
// contains.
var allowedDiagnostics = map[string]string{
	"ping":       "/usr/bin/ping",
	"traceroute": "/usr/bin/traceroute",
	"mtr":        "/usr/bin/mtr",
}

// runDiagnostic shells out to the requested diagnostic utility and
// returns its combined output.
func runDiagnostic(tool, target string) ([]byte, error) {
	path, ok := allowedDiagnostics[tool]
	if !ok {
		return nil, fmt.Errorf("unsupported diagnostic tool %q", tool)
	}

	// A target beginning with "-" would be parsed by the diagnostic
	// utility as a flag rather than a host argument. Reject it instead of
	// forwarding it, since none of the supported tools accept a
	// legitimate hostname or IP address that starts with a dash.
	if strings.HasPrefix(target, "-") {
		return nil, fmt.Errorf("invalid target %q", target)
	}

	cmd := exec.Command(path, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation

`exec.Command`'s first argument is the program to run, not a shell command line, so this was never shell metacharacter injection - it was full control over which executable on the host gets launched. Any string reachable through the `tool` query parameter (an absolute path to an unintended binary, a relative path resolved via `PATH`, or a name like `sh` with a `-c` payload smuggled through `target`) would execute as-is.

The fix replaces the tainted value with a lookup into a fixed map of tool name to absolute executable path. Because the request handler's own doc comment says the dashboard supports "a handful of network diagnostic utilities," the set of valid tools is a property the application already defines, not a generic pattern being retrofitted for security - so an allowlist here is the correct primary defense, not a bolted-on secondary check. Any `tool` value outside the map is rejected before `exec.Command` ever sees it, so the executable path is now always one of the fixed, hardcoded strings and never derived from request data.

`target` still reaches the child process as an argument, which `exec.Command`'s argument-array form already keeps out of a shell, so shell metacharacters in it are inert. What remains is flag injection: a `target` value starting with `-` would be parsed by `ping`/`traceroute`/`mtr` as an option rather than a host, potentially triggering tool-specific behavior (e.g. an output file flag). The added check rejects any `target` starting with `-` rather than trying to strip or escape it, since none of the supported tools accept a legitimate hostname or IP in that shape.
