## Verdict

Exploitable. Attacker-controlled input from the HTTP query parameter `target` is concatenated directly into a Windows batch command string and executed via `cmd /C`, enabling arbitrary command injection.

## Source

The `target` query parameter (`r.URL.Query().Get("target")`) is retrieved without validation and concatenated into the batch command string at line 25:

```go
batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)
```

An attacker can set `target=8.8.8.8 & whoami` to execute arbitrary commands after the ping completes.

## Fix

Remove the shell invocation and run each command separately with arguments passed as distinct parameters. Add input validation before execution:

```go
package diagnostics

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
)

// isValidTarget validates that the target is a valid hostname or IP address,
// rejecting any input that could contain shell metacharacters.
func isValidTarget(target string) bool {
	if len(target) == 0 || len(target) > 255 {
		return false
	}
	// Allowlist: alphanumeric, dots (domain/IPv4), hyphens (domain), colons (IPv6), brackets (IPv6 literal notation)
	for _, c := range target {
		allowed := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
		          (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':' || 
		          c == '[' || c == ']'
		if !allowed {
			return false
		}
	}
	return true
}

func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Validate target against strict allowlist before any command execution
	if !isValidTarget(target) {
		http.Error(w, "invalid target format", http.StatusBadRequest)
		return
	}

	// Run ping.exe directly with separate arguments (no shell invocation)
	pingCmd := exec.Command("ping", "-n", "4", target)
	pingOutput, err := pingCmd.CombinedOutput()
	if err != nil {
		http.Error(w, "ping command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Run nslookup directly with separate arguments (no shell invocation)
	nslookupCmd := exec.Command("nslookup", target)
	nslookupOutput, err := nslookupCmd.CombinedOutput()
	if err != nil {
		http.Error(w, "nslookup command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Combine outputs to preserve original behavior
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(pingOutput)
	w.Write([]byte("\n"))
	w.Write(nslookupOutput)
}
```

## Explanation

The fix eliminates the shell invocation by removing the `cmd /C` pattern and instead invoking `ping.exe` and `nslookup.exe` directly as separate commands with their arguments passed as distinct parameters to `exec.Command()`. This prevents cmd.exe from parsing and interpreting shell metacharacters in the target value.

Input validation via the `isValidTarget()` allowlist provides a secondary defence layer by rejecting any characters that could be shell metacharacters (`;`, `|`, `&`, `$`, backticks, etc.). The allowlist accepts only characters valid in hostnames and IP addresses: alphanumeric characters, dots, hyphens, colons, and brackets. This ensures that only legitimate network addresses reach the command execution.

The fix preserves the original contract: it still runs both diagnostic commands and combines their output for the response, but does so safely without shell interpretation.

## Behaviour changes

- The combined output now includes a newline separator between ping and nslookup results instead of being on the same line.
- Invalid target formats (those containing shell metacharacters or other dangerous characters) now return HTTP 400 Bad Request instead of being passed to the commands, rejecting suspicious input early.
- Error messages remain the same structure but may now occur at the validation step for malformed input.
