## Verdict

Real vulnerability. Shell invocation with concatenated untrusted input enables arbitrary command execution.

## Source

Line 10: `host := r.URL.Query().Get("host")` — untrusted HTTP query parameter.

Data flows through line 16 (`fmt.Sprintf("traceroute -m 15 %s", host)`) into line 18 (`exec.Command("sh", "-c", cmdLine)`), where it is executed as shell syntax.

## Fix

```go
package main

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
)

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	// Validate host to prevent injection: must be a valid hostname or IP
	if !isValidHost(host) {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("traceroute", "-m", "15", host)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "traceroute failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

func isValidHost(host string) bool {
	// Reject values starting with dash (CWE-88: argument injection prevention)
	if len(host) == 0 || host[0] == '-' {
		return false
	}
	// Must parse as valid hostname or IP address
	if net.ParseIP(host) != nil {
		return true
	}
	// Alternatively, treat as hostname — in production, perform DNS validation
	// For this endpoint, parse succeeded (IP) or hostname format is acceptable
	return host == "." || (len(host) <= 253 && !containsShellChars(host))
}

func containsShellChars(s string) bool {
	shellChars := ";|&$`\n()<>\\\"'"
	for _, c := range s {
		if c < 32 || c > 126 || (c >= 0 && containsRune(shellChars, c)) {
			return true
		}
	}
	return false
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func main() {
	http.HandleFunc("/traceroute", tracerouteHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix eliminates the shell invocation entirely. Instead of building a command string and passing it to `sh -c`, each argument is passed as a separate parameter to `exec.Command("traceroute", "-m", "15", host)`. This removes the shell metacharacter injection point because the shell interpreter is not invoked at all — `traceroute` receives the `host` value as a single argument, not as shell syntax.

The `isValidHost()` validation adds a secondary defence layer required by CWE-78 guidance: it rejects leading dashes (preventing CWE-88 argument injection) and verifies the input is either a valid IP address or a hostname-shaped string free of shell metacharacters. An attacker cannot inject commands even if validation is bypassed, because there is no shell to interpret the injected syntax.

The fix preserves the original contract: `CombinedOutput()` result is written unchanged to the response, and error handling remains identical.

## Behaviour changes

No functional changes for valid input. For invalid input: the handler now rejects hosts containing shell metacharacters or leading dashes with a 400 response, instead of passing them to `traceroute`. This is a hardening, not a regression — `traceroute` would reject such input anyway (or execute attacker-controlled commands), so the earlier rejection prevents confusion and closes the injection window.
