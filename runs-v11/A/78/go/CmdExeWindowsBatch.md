## Verdict

**Vulnerable**: The `target` query parameter is not validated before being interpolated into a batch command string passed to `cmd.exe`. An attacker can inject arbitrary Windows commands using special characters like `&`, `|`, `;`, and newlines.

## Source

```go
target := r.URL.Query().Get("target")
batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)
cmd := exec.Command("cmd", "/C", batchLine)
```

The `target` parameter flows from untrusted user input directly into the shell command string without validation or escaping. When passed to `cmd.exe /C`, the Windows command interpreter treats special characters as command separators or operators (e.g., `8.8.8.8 & malicious.exe`, `8.8.8.8 | whoami`).

## Fix

Validate that `target` is a valid hostname or IP address before using it in the command. Use Go's `net` package to parse and validate the input:

```go
import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
)

func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Validate target is a valid IP address or hostname
	if net.ParseIP(target) == nil {
		// If not a valid IP, check if it's a valid hostname (simple check)
		if len(target) == 0 || len(target) > 253 {
			http.Error(w, "invalid target format", http.StatusBadRequest)
			return
		}
		// Reject if target contains special shell characters
		for _, r := range target {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '.' || r == '-') {
				http.Error(w, "invalid target format", http.StatusBadRequest)
				return
			}
		}
	}

	batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)
	cmd := exec.Command("cmd", "/C", batchLine)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}
```

## Explanation

The vulnerability occurs because `target` is user-controlled and used directly in a shell command string. Even though `exec.Command` with an argument array would normally be safer than a shell string, here the entire command is passed as a single string argument to `cmd /C`, which still interprets special characters.

The fix validates that `target` contains only characters valid in hostnames and IP addresses:
- `net.ParseIP()` validates IPv4 and IPv6 addresses
- For hostnames, validation checks length and restricts characters to alphanumerics, dots, and hyphens (valid DNS hostname characters)
- Any attempt to inject shell metacharacters (`&`, `|`, `;`, `(`, `)`, `<`, `>`, backtick, newline, etc.) is rejected before the command is built

This whitelist approach ensures that only legitimate hostnames and IP addresses reach the command, preventing command injection while still allowing the diagnostic commands to function normally.
