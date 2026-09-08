## Verdict

**CONFIRMED**: OS Command Injection (CWE-78). The `tool` query parameter from `r.URL.Query().Get("tool")` at line 13 flows untrusted to the executable name in `exec.Command(tool, "-c", "4", target)` at line 35. An attacker can execute any binary in the system's PATH or provide an absolute path to a malicious executable.

## Source

**Source** (line 13): `tool := r.URL.Query().Get("tool")`

**Sink** (line 35): `cmd := exec.Command(tool, "-c", "4", target)`

**Data flow**: The HTTP query parameter `tool` is extracted without validation and passed directly as the executable name to `exec.Command()`, allowing execution of arbitrary binaries. An attacker can exploit this via PATH manipulation by placing a malicious executable in a writable directory that appears in PATH before the standard location, or by providing an absolute path to a malicious binary.

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

// allowedTools maps user-friendly tool names to their absolute paths
// to prevent PATH injection attacks.
var allowedTools = map[string]string{
	"ping": "/bin/ping",
}

// runDiagnostic shells out to the requested diagnostic utility and
// returns its combined output. Only whitelisted tools are permitted,
// and the target is validated to prevent flag injection.
func runDiagnostic(tool, target string) ([]byte, error) {
	toolPath, ok := allowedTools[tool]
	if !ok {
		return nil, fmt.Errorf("unknown or disallowed tool: %s", tool)
	}

	// Reject targets starting with - to prevent flag injection.
	// ping does not support -- as an end-of-options marker.
	if len(target) > 0 && target[0] == '-' {
		return nil, fmt.Errorf("invalid target: must not start with -")
	}

	cmd := exec.Command(toolPath, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

**Verification**: Code passes `go vet` with no errors.

## Explanation

The fix eliminates the OS command injection vulnerability using two complementary controls:

1. **Executable allowlist with absolute paths**: The `allowedTools` map whitelists only known-safe diagnostic tools, each mapped to its absolute path (`/bin/ping` instead of `ping`). This prevents PATH manipulation attacks where an attacker places a malicious binary in a writable directory that appears in the PATH before the standard location. The user-supplied `tool` parameter is validated against this allowlist before being used; requests for unknown tools return an error.

2. **Target parameter validation**: The `target` parameter is validated to reject leading hyphens, preventing flag injection attacks. For example, if a caller passed `target="-i 1"`, `ping` would interpret it as a flag setting the interval rather than as a hostname. Since `ping` does not support `--` as an end-of-options marker, rejecting leading hyphens is the appropriate safety mechanism.

These changes align with the CWE-78 remediation guidance: invoke the program by absolute path to avoid PATH ambiguity, and validate input only where the application defines its format (the allowlist of known tools).

## Behaviour changes

- **Tool validation**: Requests with a `tool` parameter not in the allowlist (currently only "ping") now receive a 500 error response with message "diagnostic failed: unknown or disallowed tool: <name>". Previously, any tool name would be passed to the system.
- **Target validation**: Requests with a `target` parameter starting with a hyphen now receive a 500 error response with message "diagnostic failed: invalid target: must not start with -". Previously, such targets would be passed as-is to `ping`, where they would be interpreted as flags.
- **Execution safety**: All commands are now executed with absolute paths, eliminating PATH-based code injection.
