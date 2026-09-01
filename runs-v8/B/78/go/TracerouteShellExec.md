## Verdict

Exploitable. Untrusted user input from the `host` query parameter is directly interpolated into a shell command string without validation, allowing arbitrary command injection via shell metacharacters.

## Source

`r.URL.Query().Get("host")` (line 10) - untrusted HTTP query parameter

## Fix

**Vulnerable code:**

```go
func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
	// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
	cmd := exec.Command("sh", "-c", cmdLine)
	// ... rest of function
}
```

**Fixed code:**

```go
func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	// Validate host against allowlist - only alphanumerics, dots, hyphens, colons (IPv6)
	if !regexp.MustCompile(`^[a-zA-Z0-9.\-:]+$`).MatchString(host) {
		http.Error(w, "invalid host format", http.StatusBadRequest)
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
```

Additionally, add `"regexp"` to the imports at the top of the file.

## Explanation

The fix eliminates shell invocation entirely. Instead of concatenating the host into a shell command string passed to `sh -c`, the arguments are now passed separately to `exec.Command("traceroute", "-m", "15", host)`. Without a shell interpreter, shell metacharacters in the host parameter are treated as literal argument data, not command syntax. The allowlist validation using regex rejects any host containing characters outside the set of valid hostname/IP characters, providing defense-in-depth by catching malformed input before it reaches the sink.

## Behaviour changes

- Shell invocation removed: command is now executed directly as a process, not through `sh -c`
- Arguments passed separately: `-m` and `15` are now individual arguments to `exec.Command` instead of being embedded in a shell string
- Validation added: hosts are now validated against a strict allowlist pattern before execution, rejecting any containing characters outside alphanumerics, dots, hyphens, and colons
- All other behavior preserved: `CombinedOutput()` return value, error handling, and HTTP response handling remain unchanged
