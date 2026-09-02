# CWE-78: OS Command Injection - TracerouteShellExec.go

## Verdict

Exploitable. Confidence: high.

The `host` query parameter is attacker-controlled, reaches an `sh -c` invocation with no validation or escaping anywhere on the path, and the command string is built with direct string interpolation. A value such as `host=127.0.0.1; cat /etc/passwd` or `host=$(id)` is executed as shell syntax rather than treated as data.

## Source

`tracerouteHandler`, `TracerouteShellExec.go` line 10:

```go
host := r.URL.Query().Get("host")
```

`host` comes straight from the HTTP request's query string. The only existing check (line 11) rejects an empty string; nothing constrains its character set before it reaches the sink.

Data flow: `r.URL.Query().Get("host")` (line 10) -> `fmt.Sprintf("traceroute -m 15 %s", host)` (line 16, string interpolation, no escaping) -> `exec.Command("sh", "-c", cmdLine)` (line 18, sink) -> `cmd.CombinedOutput()` (line 20).

Sink contract before the fix: `cmd.CombinedOutput()` returns the process's combined stdout+stderr as `output []byte` plus an `error`; on error the handler discards the actual error text and returns a generic 500 ("traceroute failed"); on success it writes `output` verbatim as `text/plain`. No timeout, no working-directory or environment restriction, and the binary is resolved via `PATH` through the shell rather than an absolute path.

## Fix

Vulnerable code:

```go
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
cmd := exec.Command("sh", "-c", cmdLine)

output, err := cmd.CombinedOutput()
```

Fixed code:

```go
package main

import (
	"context"
	"net/http"
	"os/exec"
	"regexp"
	"time"
)

var validHost = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}
	if !validHost.MatchString(host) {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/traceroute", "-m", "15", host)

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

Running traceroute is the point of this endpoint, so the remediation keeps the process execution and makes it safe rather than removing it. Two changes close the injection: the shell is eliminated (`exec.Command("sh", "-c", cmdLine)` becomes `exec.CommandContext(ctx, "/usr/sbin/traceroute", "-m", "15", host)`, so `host` is passed as its own argv element and shell metacharacters like `;`, `|`, `&&`, or `$()` are inert argument data, never command syntax), and `host` is validated against a strict hostname allowlist (`validHost`) before use, as the required secondary defence layer. The regex anchors on a leading and trailing alphanumeric character, so a value cannot start with `-`, which also forecloses argument injection (CWE-88) against `traceroute`'s flag parsing - a bare allowlist that permitted a leading hyphen would not have. The binary is invoked by absolute path (`/usr/sbin/traceroute`) rather than resolved through the shell's `PATH`, per the guidance's PATH-hijack defence, and `exec.CommandContext` with a bounded timeout replaces the untimed `exec.Command`, preventing a slow or unresponsive target from hanging the handler indefinitely. The success and failure paths are otherwise unchanged: `cmd.CombinedOutput()` is still written verbatim as `text/plain` on success, and a failure still returns the same generic 500 without leaking the underlying error.

## Behaviour changes

- Added allowlist validation on `host` (regex `^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`): requests whose `host` contains anything outside letters, digits, `.`, and internal `-` now get `400 invalid host parameter` instead of being executed. This is the required secondary defence and is the intended effect of the fix, but it does narrow accepted input - notably it excludes IPv6 literals (which contain `:`). If the endpoint must support IPv6 targets, the allowlist needs to be extended; flagged as an assumption since the original code's intended scope for `host` is not specified beyond "host parameter".
- Command is invoked directly instead of via `sh -c`: shell metacharacters in `host` are now literal argument data rather than shell syntax. This is the primary fix for the reported weakness.
- Binary invoked by absolute path `/usr/sbin/traceroute` instead of being resolved via `PATH` inside the shell. This defends against a writable-`PATH` substitution as recommended by the guidance, but is an assumption about the deployment's install location (common on Debian/Ubuntu-based systems) - confirm the actual path before deploying, or resolve it once at startup via `exec.LookPath` and fail fast if absent.
- Added a 30-second timeout via `exec.CommandContext` tied to the request context. The original had no timeout and could block the handler goroutine indefinitely on a slow or unresponsive network path; a run that now exceeds 30 seconds is terminated and reported as the existing generic 500 ("traceroute failed") instead of eventually completing or hanging. This is a hardening addition beyond the injection fix itself, in line with the guidance's timeout recommendation for unavoidable process execution.
- Output handling on success (write `output` as `text/plain`) and on failure (generic 500, no error detail leaked) is unchanged from the original.
