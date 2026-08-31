## Verdict

Confirmed. The `host` query parameter is attacker-controlled and is concatenated directly into a shell command string that is then executed via `sh -c`, allowing arbitrary OS command injection (e.g. `host=example.com;cat /etc/passwd` or `host=$(id)`).

## Source

`r.URL.Query().Get("host")` at line 10 in `tracerouteHandler` (`e:/Github/cwe-advisor/evals/cases/78/go/TracerouteShellExec/TracerouteShellExec.go`).

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

	// Reject anything that isn't a plain IP address or hostname before it
	// ever reaches a subprocess argument.
	if net.ParseIP(host) == nil {
		if _, err := net.LookupHost(host); err != nil {
			http.Error(w, "invalid host parameter", http.StatusBadRequest)
			return
		}
	}

	// Invoke the traceroute binary directly with an argument vector -
	// no shell is involved, so shell metacharacters in host cannot be
	// interpreted, and host can never be read as a flag because it's the
	// last positional argument after fixed flags.
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

The original code built a shell command line with `fmt.Sprintf` and handed it to `sh -c`. Any shell metacharacter in `host` (`;`, `|`, `&&`, backticks, `$(...)`, etc.) is interpreted by the shell rather than treated as part of a hostname, giving a requester full command execution as the server process.

The fix removes the shell entirely: `exec.Command("traceroute", "-m", "15", host)` invokes the `traceroute` binary directly with an argument array, so the OS passes `host` to the program as a single literal argument - no shell ever parses it, so metacharacters have no special meaning. The `-m 15` flag is a fixed literal supplied by the program, not user input, so there is no separate flag-injection surface from that argument; `host` is always the final positional value, so it can't be misread as introducing a new flag to `traceroute` itself (traceroute treats the last non-flag token as the target).

A `net.ParseIP` / `net.LookupHost` check is added ahead of the exec call as defense in depth: it rejects values that aren't a valid IP address or resolvable hostname (for example a bare `-` prefixed string, or values with embedded control characters) before they ever become a subprocess argument, rather than relying solely on the argument-array boundary.
