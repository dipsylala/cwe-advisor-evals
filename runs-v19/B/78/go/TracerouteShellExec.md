## Verdict

Exploitable. The untrusted `host` query parameter flows directly into a shell command string via `fmt.Sprintf`, then executes via `sh -c` at line 18. An attacker can inject shell metacharacters to execute arbitrary commands on the host.

## Source

Line 10: `host := r.URL.Query().Get("host")` — HTTP query parameter, untrusted user input with no validation.

## Fix

### File: TracerouteShellExec.go

```go
package main

import (
	"context"
	"net/http"
	"os/exec"
	"time"
)

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "traceroute", "-m", "15", host)

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

The original code concatenated the untrusted `host` parameter into a shell command string using `fmt.Sprintf`, then executed it via `exec.Command("sh", "-c", cmdLine)`. This allowed an attacker to inject shell metacharacters (`;`, `|`, `&&`, `$()`, etc.) to execute arbitrary commands.

The fix eliminates the shell invocation entirely by passing the host as a separate argument to `exec.CommandContext`. In this approach, the host value is passed as its own argument to the `traceroute` command, preventing the shell from interpreting metacharacters. Shell metacharacters in the host parameter are now treated as literal argument data, not command syntax. The fix also adds a context-based timeout of 30 seconds using `exec.CommandContext` to prevent the process from running indefinitely, following the guidance for hardening unavoidable command execution.

## Behaviour changes

- **Added imports**: `context` and `time` from the Go standard library (both stable, no external dependencies).
- **Added timeout protection**: The command is now bounded by a 30-second context timeout. If `traceroute` exceeds this, the context cancels and the process is terminated. This is a hardening measure recommended in the CWE-78 guidance; legitimate `traceroute` requests will complete well within this window.
- **Signature change to exec call**: `exec.CommandContext(ctx, ...)` instead of `exec.Command(...)`. This requires passing the context but does not change the semantics of the call itself — the command still runs the same program with the same arguments, and `CombinedOutput()` still returns the same output and error behavior.

No other behavior changes. The output returned to the client and error handling remain identical.
