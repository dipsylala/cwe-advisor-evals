## Verdict
Confirmed real issue.

## Source
The `host` parameter from `r.URL.Query().Get("host")` at line 10 flows unsanitized into the shell command string constructed at line 16.

## Fix

```go
func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	// Validate host to prevent option/command injection
	if len(host) == 0 || host[0] == '-' {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Use argument array instead of shell invocation
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

## Explanation
The original code invokes the shell with `exec.Command("sh", "-c", cmdLine)`, passing a dynamically constructed command string. An attacker can inject shell metacharacters and commands; for example, a `host` parameter of `example.com; rm -rf /` executes arbitrary commands.

The fix removes shell invocation entirely by passing arguments as an array directly to `exec.Command("traceroute", "-m", "15", host)`. This prevents shell metacharacter interpretation. Added validation rejects hosts beginning with `-` to prevent option injection attacks against the traceroute tool itself (e.g., `-I`, `-g`, or other flags that could alter its behavior in unsafe ways).
