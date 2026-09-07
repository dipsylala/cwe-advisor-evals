## Verdict
CONFIRMED. User-controlled input from the URL query parameter flows directly into a shell command passed to `cmd.exe /C` without validation, allowing OS command injection via shell metacharacters.

## Source
The vulnerability is in the `diagnosticsHandler` function. Line 16 retrieves untrusted user input:
```
target := r.URL.Query().Get("target")
```

Line 25 incorporates this directly into a shell command string:
```
batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)
```

Line 28 executes this string through `cmd.exe`:
```
cmd := exec.Command("cmd", "/C", batchLine)
```

When passed to `cmd /C`, shell metacharacters in `target` (like `&`, `|`, `;`) are interpreted as command separators, not as literal characters, enabling arbitrary command execution.

## Fix

### File: diagnostics.go

```go
// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
	"fmt"
	"net"
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

	// Validate that target is a safe hostname or IP address.
	// This prevents shell metacharacter injection via cmd.exe.
	if err := validateTarget(target); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Build the batch command line the way an operator would type it at a
	// cmd.exe prompt: ping the target a few times, then look up its DNS
	// record so both results show up in one diagnostic report.
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

// validateTarget checks that the target is a valid IP address or hostname,
// rejecting any input that could contain shell metacharacters.
func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	// If it parses as an IP address, it is safe.
	if net.ParseIP(target) != nil {
		return nil
	}

	// Otherwise, validate as a hostname:
	// Allow only alphanumerics, dots, and hyphens.
	// Must not start or end with a dot or hyphen.
	if strings.HasPrefix(target, ".") || strings.HasPrefix(target, "-") ||
		strings.HasSuffix(target, ".") || strings.HasSuffix(target, "-") {
		return fmt.Errorf("invalid target format")
	}

	for _, r := range target {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '.' ||
			r == '-') {
			return fmt.Errorf("invalid target: contains disallowed characters")
		}
	}

	return nil
}
```

## Explanation
The fix adds a `validateTarget()` function that restricts the `target` parameter to syntactically valid IP addresses and hostnames before constructing the shell command. The validation uses Go's standard `net.ParseIP()` to accept any valid IPv4 or IPv6 address, and for non-IP inputs, it verifies that only alphanumerics, dots, and hyphens are present—characters that cannot trigger shell interpretation in `cmd.exe`.

This approach preserves the original functionality (running `ping` and `nslookup` against a target and chaining them with `&&` in a single shell command) while eliminating the injection vector. The handler now rejects any input containing shell metacharacters before it reaches the command execution, returning HTTP 400 Bad Request for invalid targets.
