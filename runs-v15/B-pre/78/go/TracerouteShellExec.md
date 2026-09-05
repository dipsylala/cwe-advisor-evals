## Verdict
Exploitable

## Source
Line 10: `host := r.URL.Query().Get("host")` — untrusted HTTP query parameter

## Fix

**Vulnerable Code:**
```go
func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
	// Unsafe concatenation into shell command
	cmd := exec.Command("sh", "-c", cmdLine)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "traceroute failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}
```

**Fixed Code:**
```go
package main

import (
	"fmt"
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

	// Validate host against allowlist pattern (IPv4, IPv6, or domain names)
	// Reject hosts starting with dash to prevent flag injection
	hostPattern := regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)
	if !hostPattern.MatchString(host) || host[0] == '-' {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Use separate arguments instead of shell invocation
	cmd := exec.Command("traceroute", "-m", "15", host)

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

The vulnerability occurs because untrusted `host` data flows directly into a formatted command string passed to a shell invocation (`sh -c`), allowing attackers to inject arbitrary shell metacharacters and commands. The fix eliminates shell invocation entirely by passing `traceroute` and its arguments as separate parameters to `exec.Command()`. This prevents shell interpretation of metacharacters in the host value. Input validation using a strict allowlist pattern adds a secondary defense layer, rejecting hosts with unexpected characters and hosts starting with a dash (which could be misinterpreted as command-line flags by traceroute). The fix preserves the original behavior: separate arguments are accepted by `exec.Command`, and `CombinedOutput()` still returns both stdout and stderr as before.

## Behaviour changes

- Added `regexp` import for input validation
- Replaced shell-based invocation with direct command execution using separate arguments (`"traceroute", "-m", "15", host`)
- Added input validation using `regexp.MatchString()` before command execution to reject invalid hosts and prevent flag injection
- Both changes are necessary: the parameterized execution prevents shell injection, and the allowlist validation prevents the validated value from being misinterpreted as a flag by the traceroute program itself (CWE-88 defense-in-depth)
