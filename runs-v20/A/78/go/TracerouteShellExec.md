## Verdict

Confirmed. `host` is taken directly from the untrusted query string, interpolated into a shell command string with `fmt.Sprintf`, and that string is handed to `sh -c` via `exec.Command("sh", "-c", cmdLine)`. Any shell metacharacter in `host` (e.g. `; rm -rf /`, `$(...)`, backticks, `|`) is interpreted by the shell, giving full OS command injection.

## Source

`host := r.URL.Query().Get("host")` in `tracerouteHandler` (TracerouteShellExec.go:10) - an HTTP query parameter, fully attacker-controlled, flowing unmodified into the shell string built on line 16 and executed on line 18.

## Fix

### File: TracerouteShellExec.go
```go
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
)

// hostPattern accepts a bare hostname/FQDN or IPv4/IPv6 literal: letters, digits,
// dots, hyphens, colons (for IPv6). It must not start with '-' so the value can
// never be read as a flag by traceroute, and it excludes every shell metacharacter.
var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,253}$`)

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}
	if !hostPattern.MatchString(host) {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Run traceroute directly with an argument array - no shell is invoked, so
	// shell metacharacters in host cannot be interpreted. hostPattern above also
	// blocks a leading '-', so host cannot be misread as a traceroute flag.
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

The original code builds a shell command line with `fmt.Sprintf("traceroute -m 15 %s", host)` and runs it through `sh -c`, so the shell re-parses the whole string - any metacharacter in `host` (`;`, `|`, `&&`, backticks, `$()`, etc.) is executed as shell syntax rather than passed as data. Two changes close this:

1. **Remove the shell entirely.** `exec.Command("traceroute", "-m", "15", host)` passes `host` as a single argv element straight to the `traceroute` binary via `execve`-style invocation, with no shell in between to reinterpret it. This alone eliminates shell metacharacter injection (`; rm -rf /`, `$(whoami)`, etc.).
2. **Constrain the value's own format.** An argument array closes shell injection but not option/flag injection: `traceroute` still parses its own argv, so a value like `-oOutputFile` (or a bare `--help`) could be read as a flag rather than a hostname if it reached the binary un-checked. Since `host` has an application-defined format (a hostname or IP literal), validating it with `hostPattern` is a legitimate allowlist rather than a bolted-on security feature: it accepts letters, digits, `.`, `-`, and `:` (for IPv6 literals) and forbids a leading `-`, so the value can never be mistaken for a flag and cannot carry shell metacharacters either. Anything that isn't a plausible hostname/IP is rejected with a 400 rather than silently stripped, so no invalid value is passed through in a mangled form.

Together this removes the injection primitive (no shell parses the string) and closes the residual flag-injection gap that an argument array alone does not cover, while still accepting every legitimate hostname or IP a caller would supply to `traceroute`.
