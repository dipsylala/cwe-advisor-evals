## Verdict

Exploitable. The host parameter from the URL query string is directly interpolated into a shell command string via `fmt.Sprintf` and executed with `sh -c`, allowing arbitrary shell command injection.

## Source

Line 10: `host := r.URL.Query().Get("host")` — attacker-controlled URL query parameter.

The unsanitized host value flows directly to the vulnerable sink at line 18 via the intermediate string concatenation at line 16.

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

	// Reject values starting with dash to prevent flag injection
	if len(host) > 0 && host[0] == '-' {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Use exec.Command with separate arguments (no shell)
	// This prevents shell metacharacter injection
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

The original code invoked a shell (`sh -c`) with a concatenated command string, which interprets shell metacharacters in the host parameter. The fix eliminates shell invocation entirely by passing each argument separately to `exec.CommandContext`. This prevents the shell from interpreting metacharacters like `;`, `|`, `&&`, or `$()` in the host value.

The fix also adds validation to reject host values starting with a dash, preventing flag injection into the traceroute command itself (CWE-88). While separate arguments prevent shell metacharacter injection, a value passed as its own argument can still be interpreted as a command-line flag by the target program; rejecting leading dashes blocks this secondary attack vector.

Addition of `exec.CommandContext` with a 30-second timeout provides defense-in-depth by bounding execution time and allowing the handler to respect request context cancellation.

The fix preserves the original behaviour: it returns the same `CombinedOutput()` result to the client, with the same Content-Type header.

## Behaviour changes

- Shell invocation removed: `sh -c` is eliminated, preventing shell metacharacter interpretation
- Arguments passed separately: traceroute command and options are now passed as distinct arguments to exec.Command, matching the API design
- Validation added: host values starting with `-` are rejected with HTTP 400, preventing flag injection
- Timeout added: command execution is bounded to 30 seconds via exec.CommandContext, matching HTTP handler best practices
- Request context propagated: CommandContext uses the request's context, allowing request cancellation to terminate execution
