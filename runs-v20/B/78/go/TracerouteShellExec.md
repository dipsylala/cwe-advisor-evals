## Verdict

exploitable

- cwe_id: CWE-78
- location: `TracerouteShellExec.go`, line 18 (sink); tainted value originates line 10
- confidence: high

## Source

`r.URL.Query().Get("host")` in `tracerouteHandler` (line 10) - the `host` query parameter of an HTTP request, fully attacker-controlled. It is checked only for emptiness (line 11-14); no other validation or encoding is applied before it reaches the sink.

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

	// "--" ends option parsing so a host value beginning with "-" cannot be
	// read as a traceroute flag (argument injection); it rejects nothing.
	cmd := exec.CommandContext(ctx, "traceroute", "-m", "15", "--", host)

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

The handler's purpose is to run `traceroute` - there is no Go standard-library equivalent (traceroute requires ICMP/UDP TTL-probing at the socket level, the same category the CWE-78 Go guidance calls out for `ping`), so removing the command would be a regression, not a fix. The vulnerability was that the host was interpolated with `fmt.Sprintf` into a single string handed to `sh -c`, so shell metacharacters in `host` (e.g. `; rm -rf /`, `$(cmd)`, backticks) were parsed by the shell as command syntax rather than as data. The fix drops `sh -c` and the string concatenation entirely and calls `traceroute` directly with `host` as its own `exec.Command` argument, so the OS passes it to the child process as inert argv data - no shell is ever invoked to reinterpret it. A literal `--` is inserted before `host` so a value starting with `-` (e.g. `-4`, `--help`) cannot be read as a `traceroute` flag (CWE-88 argument injection); this rejects no legitimate hostname or IP. `exec.CommandContext` with a 30s timeout bounds the process per the Go guidance's "unavoidable execution" hardening step, replacing the plain `exec.Command`. No hostname allowlist/regex was added: the Go guidance explicitly warns that a hostname is not a value the application owns the format of (unlike, say, an interface name from a fixed list), and an invented pattern would reject legitimate values such as IPv6 addresses.

## Behaviour changes

- Added `context.WithTimeout(r.Context(), 30*time.Second)` and switched `exec.Command` to `exec.CommandContext`: the original had no timeout and could hang indefinitely on an unreachable host; this bounds it. This is additive hardening called for by the Go guidance ("Use `exec.CommandContext` with a timeout to bound any unavoidable process execution"), not a requirement to close the injection itself - noting it since it changes error-timing behavior (a slow host now fails after 30s instead of whatever `traceroute -m 15` would eventually return).
- Inserted a literal `--` argument before `host`: not present in the original command line. It changes no accepted input - it rejects nothing - but it does close the argument-injection gap (CWE-88) that array-form `exec.Command` alone does not.
- `fmt` import removed (no longer used, since the `fmt.Sprintf`-built command string is gone).
- Return value, output handling (`cmd.CombinedOutput()`, `w.Write(output)`), error handling, response headers, and the missing-host check are all unchanged from the original.
- No absolute path was substituted for `"traceroute"` (still resolved via `PATH`, as the original was via `sh`'s `PATH` lookup for the shell itself and implicitly for the traceroute invocation inside `cmdLine`). Flagged rather than changed: the target module's Go toolchain version is unknown (no `go.mod` in the case directory), so I cannot confirm the Go 1.19+ `ErrDot` protection against cwd-relative resolution applies; hardcoding an absolute path risks being wrong across distros (e.g. `/usr/bin/traceroute` vs `/usr/sbin/traceroute`) and was left as a follow-up rather than guessed.

## Verification

`go vet` and `go build` were run against the fixed file in an isolated scratch module (a fresh `go.mod`, no other repo files) - both completed with no errors or warnings. The `traceroute` binary itself was not available in this environment to execute the fixed code, so the "`-m 15 -- <host>`" argv shape and the claim that GNU/glibc `getopt`-based `traceroute` honors `--` as an end-of-options marker are based on standard `getopt()` semantics (recognized independent of `POSIXLY_CORRECT`), not on running the actual binary - noted as an assumption, confidence lowered accordingly for that one claim.

## Assumptions

- Treated this as a "keep-and-execute-safely" case rather than "eliminate the command," per the Go CWE-78 guidance's explicit `ping`/raw-socket precedent: no Go standard library performs `traceroute`'s ICMP/UDP TTL-probing, so removing the `exec` call would remove the endpoint's function rather than fix the vulnerability.
- Assumed the `traceroute` binary invoked recognizes `--` as an end-of-options marker (standard for `getopt`-based CLIs, including the common Debian/Ubuntu `traceroute` package) - not verified against the actual binary in this environment; confidence on this specific sub-claim is medium, overall confidence remains high because the primary fix (no shell, separate argv) does not depend on it.
- Did not hardcode an absolute path to the `traceroute` binary because its install location varies by distribution and no `go.mod`/environment data was available to confirm the Go toolchain version in use; left `PATH` resolution as in the original rather than substitute an unverified path.
