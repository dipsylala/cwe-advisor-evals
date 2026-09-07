## Verdict

Exploitable. The `host` query parameter is directly concatenated into a command string executed through `sh -c`, allowing arbitrary command injection via shell metacharacters (`;`, `|`, `&&`, `$()`, etc.).

## Source

Untrusted user input from `r.URL.Query().Get("host")` at line 10, with no validation before use.

## Fix

**Vulnerable code (line 16-18):**
```go
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
cmd := exec.Command("sh", "-c", cmdLine)
```

**Fixed code:**
```go
package main

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
)

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	// Validate host is a valid hostname or IP address
	if !isValidHost(host) {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Execute traceroute with separate arguments (no shell invocation)
	cmd := exec.Command("traceroute", "-m", "15", host)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "traceroute failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// isValidHost validates that the input is a valid hostname or IPv4/IPv6 address
func isValidHost(host string) bool {
	// Reject empty strings and values starting with dash (prevents flag injection)
	if host == "" || host[0] == '-' {
		return false
	}

	// Try to parse as IP address
	if net.ParseIP(host) != nil {
		return true
	}

	// Validate as hostname: alphanumeric, dots, and hyphens only
	hostRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	return hostRegex.MatchString(host)
}

func main() {
	http.HandleFunc("/traceroute", tracerouteHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The vulnerability is eliminated by removing shell invocation entirely. Instead of passing a concatenated command string to `sh -c`, the fixed code passes "traceroute" as the program name and the user input as a separate argument to `exec.Command`. This prevents the shell from interpreting metacharacters (`;`, `|`, `$()`, etc.) as command syntax. The fix also adds input validation through `isValidHost`, which constrains the host parameter to valid IP addresses or hostnames using both `net.ParseIP` and a regex allowlist permitting only alphanumeric characters, dots, and hyphens. This validation rejects shell metacharacters and prevents flag injection by rejecting values starting with `-`, implementing the "strict allowlist" approach recommended in the Go guidance.

## Behaviour changes

- Added `isValidHost` helper function for input validation (not present in original).
- Changed from shell execution `exec.Command("sh", "-c", cmdLine)` to direct invocation `exec.Command("traceroute", "-m", "15", host)` with separate arguments.
- The function now returns HTTP 400 (Bad Request) when the host parameter fails validation, whereas the original would accept any input.
- Added imports of `net` and `regexp` packages (not previously used).
- The command execution still returns traceroute output via `w.Write(output)`, preserving the original output behavior; no data loss or new information leaks introduced.
