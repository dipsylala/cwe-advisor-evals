## Verdict
exploitable

## Source
Line 13-14: HTTP request query parameters `tool` and `target` are extracted from user input via `r.URL.Query().Get()` without validation.

## Fix
**Vulnerable code (line 35):**
```go
cmd := exec.Command(tool, "-c", "4", target)
```

**Fixed code:**
```go
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
)

// Allowed diagnostic tools mapped to their absolute paths
var allowedTools = map[string]string{
	"ping":      "/bin/ping",
	"traceroute": "/usr/bin/traceroute",
	"dig":       "/usr/bin/dig",
	"nslookup":  "/usr/bin/nslookup",
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
	// Validate tool against allowlist; break taint by using the resolved path
	toolPath, ok := allowedTools[tool]
	if !ok {
		return nil, fmt.Errorf("unsupported tool: %s", tool)
	}
	
	// Validate target to prevent argument injection (CWE-88):
	// reject values starting with '-' which could be interpreted as flags
	if len(target) > 0 && target[0] == '-' {
		return nil, fmt.Errorf("invalid target: cannot start with '-'")
	}

	cmd := exec.Command(toolPath, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation
The vulnerability arises because the untrusted `tool` parameter from the HTTP query string flows directly to `exec.Command()` as the executable name, allowing an attacker to execute any binary on the system. The fix introduces an allowlist of permitted diagnostic tools mapped to their absolute paths. The tool parameter is validated against this allowlist before use; only approved tool names resolve to execution, and the raw user input is never passed to exec.Command. Using absolute paths prevents PATH-based attacks. An additional validation rejects target values beginning with '-' to prevent argument injection (CWE-88), where a malicious target could be interpreted as a command-line flag by the diagnostic tool. After allowlist validation, the code uses only the trusted canonical value (`toolPath`) from the map, not the original user input.

## Behaviour changes
1. **Added tool allowlist validation**: The function now returns `fmt.Errorf("unsupported tool: ...")` if the tool is not in the approved map. Original behaviour had no restriction on tool name.
2. **Added target prefix validation**: The function rejects targets starting with '-' and returns `fmt.Errorf("invalid target: cannot start with '-'")` to prevent argument injection where the target could be misinterpreted as a flag.
3. **Absolute paths enforce PATH safety**: Tools are invoked by absolute path, eliminating any possibility of PATH-relative executable substitution.
4. **Return signature and error handling preserved**: The function still returns `([]byte, error)` with the same contract - on validation failure, an error is returned; on command execution failure, the error from `CombinedOutput()` flows through unchanged.

---

**Verification**: `go vet` passed successfully on the fixed code. No new imports introduced; all types (`map[string]string`, `*exec.Cmd`, `[]byte`, `error`) and functions (`fmt.Errorf`, `exec.Command`, `CombinedOutput`) are standard library and were already available in the original code.

**Assumptions**: The allowlist of permitted tools (`ping`, `traceroute`, `dig`, `nslookup`) represents the intended diagnostic tools available to users. The absolute paths shown (`/bin/ping`, etc.) are typical Unix/Linux locations; these may need adjustment based on the deployment platform (e.g., macOS paths may differ). The target validation rejecting leading '-' is a standard defence against argument injection per CWE-78 Go guidance.
