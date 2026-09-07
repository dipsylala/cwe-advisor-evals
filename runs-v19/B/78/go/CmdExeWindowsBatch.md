## Verdict

CONFIRMED - OS Command Injection via unsanitized query parameter passed to cmd.exe

## Source

Line 16: `target := r.URL.Query().Get("target")` — untrusted HTTP query parameter

Data flow: HTTP query parameter → string interpolation → shell command string → cmd.exe /C invocation (line 28)

## Fix

The vulnerability is concatenating untrusted data into a command string passed to `cmd.exe /C`. The fix is to eliminate shell invocation and pass each argument separately to `exec.Command`. On Windows, separate arguments are safely quoted by Go's `exec` package even for programs that parse the command line themselves.

Replace the shell-based approach with direct invocation of ping and nslookup executables, passing the target as a separate argument in each case.

### File: diagnostics.go

```go
// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
	"net/http"
	"os/exec"
)

// diagnosticsHandler runs a Windows diagnostic command chosen by the
// caller and returns its combined output. It is registered at
// /internal/diagnostics and is intended for use from the ops dashboard.
func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Run ping directly with the target as a separate argument,
	// not through cmd /C with a concatenated string which would
	// allow command injection.
	pingCmd := exec.Command("ping", "-n", "4", target)
	pingOutput, err := pingCmd.CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Run nslookup with the target as a separate argument.
	nslookupCmd := exec.Command("nslookup", target)
	nslookupOutput, err := nslookupCmd.CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(pingOutput)
	w.Write([]byte("\n"))
	w.Write(nslookupOutput)
}
```

## Explanation

The original code constructed a batch command string by interpolating the untrusted `target` parameter directly into a format string, then passed that string to `cmd.exe /C` for shell interpretation. This allowed an attacker to inject arbitrary commands by passing a target like `"127.0.0.1; del /s /q C:\*"` or `"localhost && powershell -c ...`.

The fix eliminates the shell indirection entirely. Instead of building a single command string for cmd.exe to parse, we invoke ping and nslookup directly as separate processes using `exec.Command`. When `exec.Command` is called with separate arguments (not a shell), the target is passed directly as an argument and is never interpreted by a shell. On Windows, Go's exec package quotes the command line using an algorithm compatible with `CommandLineToArgvW`, ensuring safe argument passing even to executables that parse the command line themselves.

The logic remains the same: ping is invoked first; if it succeeds, nslookup is invoked; output from both commands is returned. The only behavioral change is that each command now runs as a separate process invocation rather than as part of a shell pipeline, which preserves the sequential execution and error handling the original code provided.

## Behaviour changes

- Commands are now invoked directly via `exec.Command`, not through a shell (cmd.exe /C)
- Each command runs as a separate process invocation
- The `fmt` package import is removed as it is no longer needed
- Output sequence preserved: ping output followed by nslookup output with a newline separator (matching the original intent of the && operator)
- Error handling preserved: if ping fails, nslookup does not run and an error is returned (matching the original && semantics)
