# CWE-78 Go Remediation: CmdExeWindowsBatch

## Verdict

Exploitable.

## Source

**File:** `evals/cases/78/go/CmdExeWindowsBatch/diagnostics.go`
**Line:** 25 (batchLine construction) → 28 (exec.Command sink)

Untrusted data flows from the HTTP query parameter to shell command construction:
- Source: `target := r.URL.Query().Get("target")` (line 16)
- Intermediate: `batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)` (line 25)
- Sink: `cmd := exec.Command("cmd", "/C", batchLine)` (line 28)

An attacker can inject shell metacharacters (e.g., `&`, `|`, `;`, `&&`) or Windows batch syntax to execute arbitrary commands. Example payload: `localhost & whoami` results in execution of both the diagnostic commands and the `whoami` command.

## Fix

### File: diagnostics.go

```go
// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
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

	// Validate target against a strict allowlist of valid hostname and IP characters.
	// This breaks the taint by ensuring only safe characters can reach the sink.
	if !isValidTarget(target) {
		http.Error(w, "invalid target format", http.StatusBadRequest)
		return
	}

	// Run ping with target as a separate argument (never a shell string).
	// Separate arguments prevent shell metacharacter injection.
	pingCmd := exec.Command("ping", "-n", "4", target)
	pingOutput, pingErr := pingCmd.CombinedOutput()

	var output []byte
	output = append(output, pingOutput...)

	// Only run nslookup if ping succeeded, matching the original && behavior.
	if pingErr == nil {
		nslookupCmd := exec.Command("nslookup", target)
		nslookupOutput, nslookupErr := nslookupCmd.CombinedOutput()
		if nslookupErr != nil {
			http.Error(w, "diagnostic command failed: "+nslookupErr.Error(), http.StatusInternalServerError)
			return
		}
		output = append(output, nslookupOutput...)
	} else {
		http.Error(w, "diagnostic command failed: "+pingErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}

// isValidTarget validates that the target is a hostname or IP address.
// It rejects shell metacharacters and other suspicious input, allowing only
// safe characters: alphanumerics, dots, hyphens, colons (IPv6), and percent (URL encoding).
func isValidTarget(target string) bool {
	if target == "" {
		return false
	}
	validTarget := regexp.MustCompile(`^[a-zA-Z0-9.:%-]+$`)
	return validTarget.MatchString(target)
}
```

## Explanation

The original code invoked `cmd.exe /C` with a shell command string built by concatenating the untrusted `target` parameter. This allowed an attacker to inject shell metacharacters and batch syntax to execute arbitrary commands.

The fix applies two CWE-78 mitigation layers:

1. **Input validation (secondary defense):** A new `isValidTarget()` function validates the target against a strict allowlist regex `^[a-zA-Z0-9.:%-]+$`, rejecting any shell metacharacters (`&`, `|`, `;`, `()`, `$`, backticks, etc.) or other suspicious input. This limits the target to valid hostname and IPv4/IPv6 characters.

2. **Eliminate the shell (primary defense):** Instead of invoking `cmd.exe` with a concatenated shell string, the fix directly executes the actual diagnostic programs (`ping.exe` and `nslookup.exe`) via `exec.Command()` with separate argument arrays. Since no shell is invoked, shell metacharacters in the target parameter are treated as literal data, not command syntax. The Windows cmd.exe quoting rules that differ from Go's quoting algorithm (cited in the CWE-78 Go guidance) are completely bypassed.

The fix preserves the original behavior: it runs ping first, and only runs nslookup if ping succeeds (matching the original `&&` semantics), returns combined output, and handles errors the same way.

## Behaviour changes

**Added function:** `isValidTarget(string) bool` - validates the target parameter before use. Rejects requests with invalid targets by returning HTTP 400 ("invalid target format").

**Removed:** The `fmt` package import (no longer used; removed as part of cleaning up the shell-based approach).

**Added:** The `regexp` package import (required for hostname/IP validation).

**Changed error handling:** If the target is invalid, the handler now returns HTTP 400 before attempting to execute any command, preventing invalid input from reaching the exec sinks. This is a security-motivated addition.

**Execution flow change:** The original code used shell command sequencing (`&&`); the fixed code explicitly checks the exit code of ping before running nslookup. This preserves the "only run nslookup if ping succeeds" semantics while removing the shell. Functionally equivalent to the original.

**Sink contract preserved:** Both the original and fixed code return combined stdout+stderr output via `CombinedOutput()` to the HTTP response with the same content type header. Error handling for execution failures is identical. The only observable difference is that invalid hostnames are rejected before execution (HTTP 400) rather than being passed through, which is a security improvement, not a regression.
