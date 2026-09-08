## Verdict

Exploitable. The `target` query parameter is obtained directly from user input at line 16 without validation, concatenated into a batch command string at line 25 using `fmt.Sprintf`, and passed to `cmd.exe /C` at line 28. Since `cmd.exe` interprets the command line as shell syntax, an attacker can inject arbitrary commands using shell metacharacters and operators.

## Source

**Data origin**: HTTP query parameter `target` obtained at line 16 via `r.URL.Query().Get("target")`.

**Data flow**:
1. Line 16: `target := r.URL.Query().Get("target")` - untrusted user input
2. Line 25: `batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)` - target concatenated directly into a command string
3. Line 28: `cmd := exec.Command("cmd", "/C", batchLine)` - the concatenated string passed to cmd.exe for shell interpretation

**Exploitable pattern**: Any untrusted value in the `target` parameter can include shell metacharacters like `&&`, `|`, `;`, or `$()` that will be interpreted as command operators when executed through cmd.exe. For example, `target="8.8.8.8 && whoami"` would execute the `whoami` command.

## Fix

### File: diagnostics.go

```go
// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
	"bytes"
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"
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

	// Validate target to prevent flag injection.
	// Reject values starting with dash or slash (would be interpreted as flags).
	if strings.HasPrefix(target, "-") || strings.HasPrefix(target, "/") {
		http.Error(w, "invalid target parameter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var output bytes.Buffer

	// Run ping with context-based timeout, directly without cmd.exe to avoid
	// shell command injection. Each argument is passed separately, preventing
	// interpretation of special characters as shell operators.
	pingCmd := exec.CommandContext(ctx, "ping", "-n", "4", target)
	pingCmd.Stdout = &output
	pingCmd.Stderr = &output
	pingErr := pingCmd.Run()

	if pingErr != nil {
		http.Error(w, "ping command failed: "+pingErr.Error(), http.StatusInternalServerError)
		return
	}

	output.WriteString("\n\n--- DNS Lookup ---\n\n")

	// Run nslookup with context-based timeout, directly without cmd.exe.
	nslookupCmd := exec.CommandContext(ctx, "nslookup", target)
	nslookupCmd.Stdout = &output
	nslookupCmd.Stderr = &output
	nslookupErr := nslookupCmd.Run()

	if nslookupErr != nil {
		http.Error(w, "nslookup command failed: "+nslookupErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output.Bytes())
}
```

## Explanation

The fix eliminates the command injection vulnerability by invoking `ping` and `nslookup` as separate executable processes rather than passing a concatenated command string to `cmd.exe`. This removes the shell interpretation layer entirely, so special characters in the `target` parameter are treated as literal argument data rather than shell operators. Input validation rejects values starting with `-` or `/` to prevent them from being interpreted as command-line flags by the target programs. The fix also adds context-based timeouts using `exec.CommandContext` to bound process execution time, following Go best practices for command execution. All standard library APIs (`context`, `exec`, `strings`, `time`) are used; no external dependencies are required.

## Behaviour changes

- **Additional imports**: `bytes`, `context`, `strings`, `time` packages added for process execution and validation. The `fmt` package used only for the vulnerable `fmt.Sprintf` is removed.
- **Added validation**: Input is now validated to reject targets starting with `-` or `/` (interpreted as flags). This rejects invalid input but does not break legitimate hostnames or IP addresses, which do not start with these characters.
- **Timeout added**: Both commands now use `exec.CommandContext` with a 30-second timeout, preventing indefinite hangs from network operations.
- **Command execution separated**: The original code used `cmd.exe /C` to run both `ping` and `nslookup` in a single shell command connected by `&&`. The fixed code runs them as separate processes. The observable difference: if `ping` fails (host unreachable), the original code would not run `nslookup` due to the `&&` operator; the fixed code returns an error immediately without attempting `nslookup`. This is a minor behavior change but reasonable for a diagnostic endpoint, as it still provides diagnostic output on success and reports failures clearly.
- **Output separator added**: A literal separator (`\n\n--- DNS Lookup ---\n\n`) is added between ping and nslookup output for clarity, replacing the implicit separation that would have occurred in the original shell command.
