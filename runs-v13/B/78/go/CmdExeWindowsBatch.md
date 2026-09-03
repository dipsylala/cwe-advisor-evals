## Verdict

**Vulnerable**: The `target` parameter from the HTTP query string is directly concatenated into a shell command string and passed to `cmd.exe /C`, allowing OS command injection via shell metacharacters.

## Source

**CWE**: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

**File**: `evals/cases/78/go/CmdExeWindowsBatch/diagnostics.go`

**Line**: 28 (`exec.Command("cmd", "/C", batchLine)`)

**Data flow**:
1. **Source** (line 16): `target := r.URL.Query().Get("target")` — untrusted HTTP query parameter
2. **Concatenation** (line 25): `fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)` — target injected into shell command string
3. **Sink** (line 28): `exec.Command("cmd", "/C", batchLine)` — batchLine passed to shell interpreter

**Exploit scenario**: An attacker can inject shell metacharacters into the `target` parameter (e.g., `127.0.0.1; del C:\users\*`) which `cmd.exe /C` will interpret as command delimiters or piping operators, executing arbitrary commands on the host.

## Fix

Replace the shell-based command invocation with direct execution of `ping` and `nslookup` as separate processes, each receiving the target as a separate argument. Add strict input validation using an allowlist pattern to accept only valid hostname and IP address characters.

**Fixed code**:

```go
package diagnostics

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
)

// diagnosticsHandler runs Windows diagnostic commands on a validated target.
func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Validate target against an allowlist pattern before use.
	// Accepts hostnames and IP addresses; rejects shell metacharacters.
	if !isValidTarget(target) {
		http.Error(w, "invalid target format", http.StatusBadRequest)
		return
	}

	// Execute ping and nslookup as separate commands without shell invocation.
	// Passing the target as a separate argument (not concatenated into a string)
	// prevents cmd.exe or any shell from interpreting special characters.
	pingOutput, pingErr := exec.Command("ping", "-n", "4", target).CombinedOutput()
	nslookupOutput, nslookupErr := exec.Command("nslookup", target).CombinedOutput()

	// Combine output from both commands.
	var output strings.Builder
	output.Write(pingOutput)
	if pingErr != nil {
		fmt.Fprintf(&output, "\nping error: %v\n", pingErr)
	}
	output.WriteString("\n---\n\n")
	output.Write(nslookupOutput)
	if nslookupErr != nil {
		fmt.Fprintf(&output, "\nnslookup error: %v\n", nslookupErr)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(output.String()))
}

// isValidTarget validates that the target is a reasonable hostname or IP address.
// Returns true only if the target matches a strict allowlist pattern.
func isValidTarget(target string) bool {
	// First try to parse as an IP address (IPv4 or IPv6).
	if net.ParseIP(target) != nil {
		return true
	}

	// Otherwise, validate as a hostname: alphanumeric, dots, and hyphens only.
	// This blocks shell metacharacters (;, |, &, >, <, $, `, ', ", etc.).
	// Max length 253 follows DNS hostname specifications.
	matched, err := regexp.MatchString(`^[a-zA-Z0-9.-]+$`, target)
	return err == nil && matched && len(target) <= 253
}
```

## Explanation

The vulnerability existed because the `target` parameter was embedded directly into a shell command string using `fmt.Sprintf`, then passed to `cmd.exe /C`. This caused `cmd.exe` to parse the entire string as shell syntax, interpreting metacharacters like `;`, `&`, `&&`, `|`, `>`, and `<` as command delimiters rather than literal characters.

The fix eliminates shell parsing entirely:

1. **No shell invocation**: `exec.Command("ping", "-n", "4", target)` and `exec.Command("nslookup", target)` invoke the executables directly without `/C` or any shell intermediary. Go's `exec.Command` passes arguments as a separate array to the OS, not as a concatenated string.

2. **Separate arguments**: The target is passed as its own argument (the 4th and 2nd argument respectively), not concatenated into a single command string. Even if shell metacharacters appear in the target value, they are treated as literal characters by the target program.

3. **Input validation**: The `isValidTarget()` function enforces a strict allowlist accepting only characters valid in hostnames (alphanumeric, dots, hyphens) and IP addresses. This provides defense-in-depth by rejecting injected metacharacters before they reach the sink. The validation uses `net.ParseIP()` to accept both IPv4 and IPv6 addresses.

4. **Output preservation**: The fix maintains the original contract by combining output from both commands in the same format, preserving any error messages, so the endpoint behavior is functionally equivalent to the original.

## Behaviour changes

- **No output loss**: Both `ping` and `nslookup` output are combined and returned as before.
- **Error handling**: Individual errors from `ping` or `nslookup` are appended to the output instead of failing the entire request. This is more user-friendly for diagnostics.
- **Input validation**: The endpoint now returns HTTP 400 (Bad Request) for invalid target formats rather than attempting to execute them. This prevents both injection attempts and execution errors from invalid hostnames.
- **Security posture**: The endpoint no longer interprets shell syntax in user input, eliminating the command injection attack surface entirely.
