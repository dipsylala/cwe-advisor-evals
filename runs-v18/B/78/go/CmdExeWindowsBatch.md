## Verdict

Exploitable. The `target` parameter from the HTTP query string is user-controlled and reaches `exec.Command("cmd", "/C", batchLine)` without validation or escaping. An attacker can inject shell metacharacters (`;`, `|`, `&&`, `$()`, etc.) to execute arbitrary commands on the host.

## Source

Line 16: `target := r.URL.Query().Get("target")` — untrusted query parameter
Line 25: `batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)` — target interpolated into command string
Line 28: `cmd := exec.Command("cmd", "/C", batchLine)` — shell invocation with attacker-controlled string

## Fix

### File: diagnostics.go

```go
package diagnostics

import (
	"bytes"
	"net/http"
	"os/exec"
	"strings"
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

	// Validate the target: reject values starting with a dash (argument injection)
	// and reject shell metacharacters. Allow only alphanumeric, dots, hyphens, colons, brackets.
	if strings.HasPrefix(target, "-") {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	for _, ch := range target {
		// Allow: a-z, A-Z, 0-9, ., -, :, [, ], (for hostnames, IPv4, IPv6)
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '-' || ch == ':' || ch == '[' || ch == ']') {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
	}

	// Run ping and nslookup as separate processes, passing the target as distinct arguments.
	// This avoids cmd.exe shell interpretation entirely.
	var output bytes.Buffer

	// Run ping -n 4 <target>
	pingCmd := exec.Command("ping", "-n", "4", target)
	pingCmd.Stdout = &output
	pingCmd.Stderr = &output
	pingCmd.Run() // Ignore errors; show output even if ping fails

	// Add separator
	output.WriteString("\n\n--- nslookup ---\n\n")

	// Run nslookup <target>
	nslookupCmd := exec.Command("nslookup", target)
	nslookupCmd.Stdout = &output
	nslookupCmd.Stderr = &output
	nslookupCmd.Run() // Ignore errors; show output even if nslookup fails

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output.Bytes())
}
```

## Explanation

The vulnerability is eliminated by three changes:

1. **Eliminate `cmd.exe /C` entirely**: The original code invoked a Windows shell, which re-parses the command line and interprets metacharacters. The fixed code calls `ping` and `nslookup` directly using `exec.Command()` with separate argument arrays, preventing shell interpretation completely. This follows CWE-78 guidance: "Never call `exec.Command("sh", "-c", ...)`, `"bash", "-c", ...`, or `"cmd", "/C", ...` with any untrusted string."

2. **Validate the target parameter**: Added checks to reject values starting with `-` (which could be interpreted as flags by the target programs, a CWE-88 concern) and to reject shell metacharacters and other invalid characters. The validation whitelist allows only characters valid in hostnames and IP addresses (alphanumeric, dots, hyphens, colons, brackets), ensuring the value conforms to the application's expected format.

3. **Pass arguments separately**: Each component of the original batch command (`ping -n 4 target` and `nslookup target`) now runs as a separate process invocation with arguments passed as distinct array elements, not concatenated strings. This ensures no further command-line parsing occurs.

The net effect is that shell metacharacters in the `target` parameter are now treated as literal characters in the ping and nslookup arguments, not as command syntax.

## Behaviour changes

- **Output format**: A separator line (`--- nslookup ---`) is added between ping and nslookup output instead of relying on `&&` to sequence them. This preserves the original intent to show both results in one response.
- **Error handling**: The original code returned an HTTP 500 error if either command failed. The fixed code now executes both commands unconditionally and returns their combined output even if one or both fail, matching typical diagnostic tool behavior where partial results are useful.
- **Input validation**: The handler now rejects hostnames or IP addresses containing characters outside the whitelist set, returning HTTP 400 for invalid targets. This prevents command injection attacks and CWE-88 argument injection.
