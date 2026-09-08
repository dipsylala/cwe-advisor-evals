## Verdict

Confirmed. `diagnosticsHandler` builds a `cmd.exe` batch line with `fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)` and executes it via `exec.Command("cmd", "/C", batchLine)`. `target` comes straight from the `target` query parameter with no validation or escaping, so a request such as `?target=127.0.0.1 & calc.exe` (or any `&`, `&&`, `|`, `;`, backtick, or `$()` payload) is interpreted by `cmd.exe` as additional command syntax rather than as literal data, giving the caller arbitrary command execution with the privileges of the service process.

## Source

`r.URL.Query().Get("target")` (`diagnostics.go:16`) - an HTTP query parameter, fully attacker-controlled.

## Fix

### File: diagnostics.go

```go
// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	// ping.exe does not honour a "--" end-of-options marker, so a leading
	// '-' can only be an attempt to inject a flag; reject it outright.
	if strings.HasPrefix(target, "-") {
		http.Error(w, "target must not start with '-'", http.StatusBadRequest)
		return
	}

	// Run ping directly - no cmd.exe, no batch line - so target is passed
	// as its own argument and can never be reinterpreted as shell syntax.
	// Ping has no Go standard library equivalent (ICMP echo needs a raw
	// socket), so the command itself stays; invoking it by absolute path
	// avoids a writable PATH entry substituting a different binary.
	pingPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "ping.exe")

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	pingOutput, err := exec.CommandContext(ctx, pingPath, "-n", "4", target).CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The DNS lookup is incidental to the diagnostic - net.LookupHost
	// performs it natively, so nslookup and the shell invocation it
	// required are removed entirely rather than made safe.
	addrs, err := net.LookupHost(target)
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var report strings.Builder
	report.Write(pingOutput)
	report.WriteString("\nAddresses:\n")
	for _, addr := range addrs {
		fmt.Fprintf(&report, "  %s\n", addr)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(report.String()))
}
```

## Explanation

The endpoint has two distinct diagnostic purposes bundled into one batch line, and they get different treatment. `ping` is the reason the endpoint exists and has no Go standard library equivalent (ICMP echo needs a raw socket), so per the CWE-78 Go guidance it stays as a command - the fix invokes it directly with `exec.CommandContext(ctx, pingPath, "-n", "4", target)`, passing `target` as its own argument with no shell involved anywhere, and by an absolute path (`%SystemRoot%\System32\ping.exe`) so a writable `PATH` entry cannot substitute a different binary. Because `ping.exe` receives its own argument list rather than a re-parsed batch line, none of `;`, `&`, `&&`, `|`, backticks, or `$()` in `target` can act as command syntax - they are literal argument bytes. A leading `-` is rejected up front because Windows `ping.exe` has no `--` end-of-options convention, so a value starting with `-` could otherwise be read as a flag (CWE-88) rather than a target.

The `nslookup` half is incidental - it is just a DNS lookup - so it is replaced with `net.LookupHost`, which performs the same resolution natively and removes that shell invocation (and its `&&` chaining, which was itself part of the injection surface) entirely rather than trying to make it safe.

## Behaviour changes

- Output format for the DNS portion changes: the response no longer contains `nslookup`'s own text (`Server:`, non-authoritative notices, aliases) - it now lists resolved addresses under a plain `Addresses:` header. The ping portion's output text is unchanged since it still comes from `ping.exe` directly.
- A request whose `target` starts with `-` is now rejected with `400 Bad Request` (previously it would have been spliced into the batch line and likely misbehaved or been exploitable).
- Execution is now bounded by a 20-second timeout via `exec.CommandContext`; a target that caused `ping -n 4` to hang indefinitely previously could hang the request, and now fails with a `500` after 20 seconds instead.
- Failure semantics are preserved: if `ping` fails, or the DNS lookup fails, the handler returns `500` with an error message and no diagnostic text is written - matching the original's behaviour where `&&` meant either step failing discarded all output.

Verified by copying the fixed file into a scratch Go module and running `go vet ./...` and `go build ./...` (targeting both the host `windows/386` toolchain and cross-compiled `windows/amd64`) - both completed with exit code 0 and no diagnostics. Every new import (`context`, `net`, `os`, `path/filepath`, `time`) is a standard library package; `exec.CommandContext`, `net.LookupHost`, `filepath.Join`, `os.Getenv`, `strings.Builder`, and `context.WithTimeout` are all standard library APIs, none introduced by this fix beyond what the loaded CWE-78 Go guidance names or the standard library documents.
