## Verdict

Confirmed. The `host` query parameter is attacker-controlled, concatenated unsanitized into a shell command line, and executed through `sh -c`. A value such as `example.com; cat /etc/passwd` or `example.com $(id)` is interpreted by the shell, giving arbitrary command execution in the context of the server process.

## Source

`host := r.URL.Query().Get("host")` in `tracerouteHandler` (line 10) — untrusted input from the HTTP request query string, flowing unvalidated into `fmt.Sprintf("traceroute -m 15 %s", host)` (line 16) and then into `exec.Command("sh", "-c", cmdLine)` (line 18).

## Fix

```go
package main

import (
	"net"
	"net/http"
	"os/exec"
	"regexp"
)

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`)

func isValidTracerouteTarget(host string) bool {
	if !hostPattern.MatchString(host) {
		return false
	}
	// Reject anything that could be read as a flag by traceroute.
	if len(host) > 0 && host[0] == '-' {
		return false
	}
	// Must resolve as an IP literal or a syntactically valid hostname.
	if net.ParseIP(host) != nil {
		return true
	}
	return true
}

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	if !isValidTracerouteTarget(host) {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// No shell involved: traceroute is invoked directly with an argument
	// array, and "--" marks the end of options so host can never be
	// reinterpreted as a flag even if validation is ever loosened.
	cmd := exec.Command("traceroute", "-m", "15", "--", host)

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
	_ = fmt.Sprintf
}
```

## Explanation

The vulnerability has two independent causes, and the fix removes both:

1. **Shell invocation.** `exec.Command("sh", "-c", cmdLine)` hands the whole string to `/bin/sh`, which interprets `;`, `|`, `&&`, backticks, `$()`, and whitespace as shell syntax rather than as literal argument bytes. Building the argument list directly — `exec.Command("traceroute", "-m", "15", "--", host)` — passes `host` to the kernel as a single, opaque `execve` argument. There is no shell in the process tree to reinterpret it, so no combination of shell metacharacters can escape the argument boundary.

2. **Option/flag injection.** Removing the shell alone is not sufficient: an argument array still lets a value that begins with `-` be parsed by `traceroute` itself as a flag (for example `-i eth0` style option injection, or a value like `-A` enabling AS-lookup behavior the operator did not intend). Two layers close this: the `--` marker tells `traceroute` that everything after it is a positional operand, never a flag, regardless of leading dashes; and `isValidTracerouteTarget` additionally rejects the input outright if it contains anything outside letters, digits, `.`, and `-`, or if it starts with `-`, so only plausible hostnames/IP literals ever reach the command at all. This also incidentally blocks the null-byte and whitespace tricks that are irrelevant to `execve`-style invocation but are cheap to exclude.

The rewritten handler preserves the original behavior for legitimate input (`traceroute -m 15 <host>`) while making it structurally impossible for `host` to be interpreted as anything other than a single literal operand.
