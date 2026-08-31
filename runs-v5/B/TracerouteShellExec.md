## Verdict

- **CWE-78** - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Location:** `TracerouteShellExec.go`, line 18 (`exec.Command("sh", "-c", cmdLine)`), fed from line 16
- **Verdict:** exploitable
- **Confidence:** high
- **Assumptions:** none needed - the flow from the query parameter to the shell sink is direct and unvalidated

## Source

- **Source:** `r.URL.Query().Get("host")` (line 10) - the `host` query parameter of an incoming HTTP request to `/traceroute`, fully attacker-controlled.
- **Path:** `host` is checked only for emptiness (line 11-14), then interpolated directly into a command string via `fmt.Sprintf("traceroute -m 15 %s", host)` (line 16). That string is passed unmodified to `exec.Command("sh", "-c", cmdLine)` (line 18), which invokes a shell that re-parses it. Any shell metacharacter in `host` (`;`, `|`, `&&`, `$()`, backticks) is interpreted as command syntax rather than data.
- **Sink contract:** `cmd.CombinedOutput()` (line 20) returns the merged stdout+stderr bytes and an error; on error the handler discards the error detail and returns a generic 500 ("traceroute failed"); on success it writes the raw bytes back as `text/plain`. No `context`/timeout is set, and the shell (`sh`) and `traceroute` are both resolved via `PATH` rather than an absolute path.

## Fix

No third-party library is needed - this stays on Go's standard `os/exec`. Running a traceroute is the feature the endpoint exists for, so the fix keeps command execution but removes the shell and adds argument-array invocation plus allowlist validation, per `cwe/78/go/INDEX.md`.

Vulnerable code:

```go
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
// SAST FINDING: CWE-78 reported here. Sink is the next statement.
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

// validHost allows hostnames, IPv4, and IPv6 literals; the leading
// alnum requirement also blocks values that start with "-" and could
// otherwise be read as a traceroute flag (CWE-88).
var validHost = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:-]*$`)

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}
	if len(host) > 255 || !validHost.MatchString(host) {
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

The shell is removed entirely: instead of building a single string with `fmt.Sprintf` and handing it to `sh -c` (which re-parses it and treats any metacharacter in `host` as command syntax), `traceroute` is invoked directly with `host` passed as its own `exec.Command` argument, so the OS never interprets it as anything but literal argument data. Because an argument array alone stops shell metacharacter injection but not argument/flag injection, `host` is additionally checked against a strict allowlist regex that requires it to start with an alphanumeric character - this both rejects unexpected input as a secondary defence layer and specifically blocks a value like `-F` from being read as a `traceroute` flag. The allowlist check runs before the value reaches `exec.Command`, so the sink only ever sees the same tainted string after it has been positively validated, not a value reassembled downstream.

## Behaviour changes

- **Invalid `host` now rejected with 400** instead of being passed to the shell (previously any non-empty value ran, valid or not). This is required to close the injection and the CWE-88 argument-injection gap; a legitimate hostname or IPv4/IPv6 literal still matches the allowlist and is unaffected.
- **`exec.CommandContext` with a 30s timeout added** (`os/exec` sink was previously untimed). This is the hardening step named in `cwe/78/go/INDEX.md` ("bound any unavoidable process execution") rather than a requirement of the injection fix itself; a traceroute that legitimately runs longer than 30s would now be cut off where it previously was not. Adjust the duration if longer runs are expected in this deployment.
- **Binary invoked by absolute path (`/usr/sbin/traceroute`)** instead of resolving `traceroute`/`sh` via `PATH`, per the guidance's "invoke by absolute path so a writable PATH entry cannot substitute a different binary." This assumes `traceroute` is installed at that path; confirm the actual install location for the target OS/distro (e.g. `/usr/bin/traceroute` on some systems) before deploying, or resolve it at startup instead of hardcoding it.
- **Return value and error handling unchanged**: `cmd.CombinedOutput()` is still called the same way, success still writes the raw output as `text/plain`, and failure still returns the same generic 500 without leaking error detail - the sink's existing contract is preserved.
