## Verdict

The finding is a genuine CWE-78 OS command injection vulnerability. The code constructs a shell command string by concatenating user input (the `host` parameter) directly into `fmt.Sprintf("traceroute -m 15 %s", host)`, then passes it to `exec.Command("sh", "-c", ...)`. An attacker can supply `example.com; rm -rf /` or similar payloads to execute arbitrary commands.

## Source

Line 18 is the sink: `exec.Command("sh", "-c", cmdLine)` receives a command line built from user input at line 16. The source is the untrusted `host` parameter from the HTTP query string at line 10, which reaches the sink unsanitized.

## Fix

### File: TracerouteShellExec.go

```go
package main

import (
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

	// Validate host against allowlist: valid IP address or hostname
	if !isValidHost(host) {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Pass arguments separately to exec.Command to avoid shell invocation
	// The -- terminates option processing, preventing argument injection if host were to start with a dash
	cmd := exec.Command("traceroute", "-m", "15", "--", host)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "traceroute failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// isValidHost checks if the input is a valid IP address or hostname
func isValidHost(host string) bool {
	// Accept valid IP addresses (IPv4 or IPv6)
	if net.ParseIP(host) != nil {
		return true
	}

	// Accept valid hostnames: labels separated by dots, each label alphanumeric or hyphen
	// but not starting or ending with hyphen
	hostRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	return hostRegex.MatchString(host)
}

func main() {
	http.HandleFunc("/traceroute", tracerouteHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The vulnerability arises from using a shell to execute the command. By replacing `exec.Command("sh", "-c", cmdLine)` with `exec.Command("traceroute", "-m", "15", "--", host)`, the command is invoked directly without shell parsing. The Go runtime passes each argument as a separate item, preventing shell metacharacters (`;`, `|`, `$()`, etc.) from being interpreted.

The validation function `isValidHost` restricts the `host` parameter to either valid IP addresses (via `net.ParseIP`) or valid DNS hostnames (via regex). This allowlist prevents injection attempts from reaching the command at all. The regex rejects strings with leading hyphens, spaces, quotes, semicolons, and other special characters that could be misinterpreted as command options or operators.

The `--` argument terminates option processing for `traceroute`, ensuring that even if validation were somehow bypassed, a value beginning with `-` would not be interpreted as a flag. This defense-in-depth approach aligns with CWE-78 remediation guidance for Go.
