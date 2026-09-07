## Verdict

CONFIRMED - OS Command Injection via shell string concatenation.

## Source

Line 10: `host := r.URL.Query().Get("host")` — untrusted HTTP query parameter flows directly into command string construction at line 16 via `fmt.Sprintf`, then passed to shell invocation at line 18.

## Fix

Replace shell-based execution with parameterized `exec.Command` and validate the host parameter:

```go
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"time"
)

// isValidHost validates that the input is a valid hostname or IP address.
// Returns the validated host or empty string if invalid.
func isValidHost(host string) string {
	if host == "" {
		return ""
	}
	// Try parsing as IP address first
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	// Try DNS lookup to validate hostname
	// Only allow if it resolves; reject literal strings that look like options
	if _, err := net.LookupIP(host); err == nil {
		return host
	}
	return ""
}

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	// Validate host before passing to exec
	validatedHost := isValidHost(host)
	if validatedHost == "" {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Use exec.CommandContext with timeout; pass arguments separately (no shell).
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "traceroute", "-m", "15", validatedHost)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "traceroute failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

func main() {
	http.HandleFunc("/traceroute", tracerouteHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The original code concatenated the user-supplied `host` parameter into a shell command string and invoked it via `sh -c`, allowing an attacker to inject arbitrary shell commands. The fix eliminates shell invocation entirely by passing arguments to `exec.CommandContext` as a separate array — `traceroute`, `-m`, `15`, and the validated host become four discrete arguments that the kernel executes without shell interpretation. The host is validated against a strict allowlist (valid IP addresses or resolvable hostnames) before reaching the sink, rejecting malformed input upstream. `exec.CommandContext` replaces `exec.Command` to enforce a 30-second timeout, preventing indefinite hangs or resource exhaustion. The fix preserves the original contract: all command output (stdout + stderr) is still captured and returned to the HTTP response on success.

## Behaviour changes

- **Shell metacharacters are no longer interpreted**: injected `; rm -rf /` is now treated as a literal hostname argument, not a separate command.
- **Host validation is stricter**: only valid IPv4/IPv6 addresses or DNS-resolvable hostnames are accepted; malformed input returns 400 Bad Request instead of reaching the sink.
- **Command execution now has a timeout**: any traceroute invocation that takes longer than 30 seconds is cancelled, closing denial-of-service via resource exhaustion.
- **No silent failures**: a `context.DeadlineExceeded` or cancelled context still results in an error, preserving the current failure contract (HTTP 500 on execution error).
