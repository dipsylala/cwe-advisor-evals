## Verdict

Confirmed. `target` comes from the unauthenticated request query string and is concatenated directly into a `cmd.exe` batch line (`ping -n 4 %s && nslookup %s`) that is then executed with `exec.Command("cmd", "/C", batchLine)`. Because the value is interpolated into a string handed to the Windows command shell, any `cmd.exe` metacharacter in `target` (`&`, `&&`, `|`, `||`, `%...%`, `"`, newlines via URL-decoded `%0d%0a`, etc.) is interpreted by the shell rather than treated as part of a hostname, giving a caller of `/internal/diagnostics` arbitrary command execution as the service account, e.g. `target=127.0.0.1 & calc.exe` or `target=127.0.0.1 && net user attacker P@ss123! /add`.

## Source

`r.URL.Query().Get("target")` in `diagnosticsHandler` (diagnostics.go, line 16) — attacker-controlled HTTP query parameter, unvalidated, flows straight into `fmt.Sprintf` and then into `exec.Command("cmd", "/C", ...)`.

## Fix

### File: diagnostics.go
```go
// Package diagnostics exposes a small HTTP endpoint that lets on-call
// engineers run a handful of built-in Windows diagnostic commands against
// the host a service instance is running on, without needing RDP access.
package diagnostics

import (
	"bytes"
	"net/http"
	"os/exec"
	"regexp"
)

// hostnameOrIPPattern matches a bare DNS hostname/FQDN or IPv4/IPv6 literal:
// letters, digits, hyphens, dots and colons only, each label starting and
// ending with an alphanumeric character. This is the format ping/nslookup
// expect for their target argument, and it structurally excludes shell
// metacharacters (&, |, %, ", newlines) as well as a leading "-" that could
// otherwise be read as a flag.
var hostnameOrIPPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.:-]{0,253}[a-zA-Z0-9])?$`)

// diagnosticsHandler runs a Windows diagnostic command chosen by the
// caller and returns its combined output. It is registered at
// /internal/diagnostics and is intended for use from the ops dashboard.
func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	if !hostnameOrIPPattern.MatchString(target) {
		http.Error(w, "target must be a valid hostname or IP address", http.StatusBadRequest)
		return
	}

	// Run ping and nslookup as separate processes with the target passed as
	// a discrete argument, not as text substituted into a cmd.exe command
	// line. This removes the shell parser from the data path entirely, so
	// no value of target - however it is formatted - can inject additional
	// commands; the earlier validation additionally rules out the target
	// being read as a flag by either tool.
	var report bytes.Buffer

	pingCmd := exec.Command("ping", "-n", "4", target)
	pingOutput, pingErr := pingCmd.CombinedOutput()
	report.WriteString("=== ping ===\r\n")
	report.Write(pingOutput)
	if pingErr != nil {
		report.WriteString("\r\nping error: " + pingErr.Error() + "\r\n")
	}

	nslookupCmd := exec.Command("nslookup", target)
	nslookupOutput, nslookupErr := nslookupCmd.CombinedOutput()
	report.WriteString("\r\n=== nslookup ===\r\n")
	report.Write(nslookupOutput)
	if nslookupErr != nil {
		report.WriteString("\r\nnslookup error: " + nslookupErr.Error() + "\r\n")
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(report.Bytes())
}
```

## Explanation

The original code builds a `cmd.exe` batch line by string-formatting `target` into it and then executes that line through `cmd /C`, so the shell - not the application - parses the value. Any `cmd.exe` metacharacter in `target` breaks out of the intended `ping`/`nslookup` invocation and runs attacker-chosen commands with the privileges of the diagnostics service.

The fix removes `cmd.exe` from the data path entirely: `ping` and `nslookup` are invoked directly via `exec.Command` with `target` passed as its own argument, never assembled into a shell string. `exec.Command` execs the named binary directly and does not invoke a shell, so shell metacharacters in `target` are inert - they are just literal argument text. The two commands are run separately (rather than chained with `&&`) because there is no longer a shell to interpret that operator, and their outputs are concatenated in Go to preserve the original combined-report behavior.

An argument array alone would still let a `target` value like `-h` be read as a flag by `ping` or `nslookup` rather than as a hostname, so the handler also validates `target` against a hostname/IP allowlist before running anything. This is a case where the application itself defines the expected input shape - a diagnostic target is always a bare hostname, FQDN, or IPv4/IPv6 literal - so constraining it to that shape is a legitimate format check, not merely a security-only regex layered on top of an already-safe sink: it rejects malformed input, and it also happens to make a leading `-` (and any shell metacharacter) impossible to submit as `target`.

To verify: request `/internal/diagnostics?target=127.0.0.1%20^&^&%20whoami` (or any payload containing `&`, `|`, `%`, or a space) against the original handler and observe the injected command's output appended to the response; against the fixed handler the request is rejected with a 400 before any process is started. A benign request such as `/internal/diagnostics?target=127.0.0.1` or `?target=example.com` should still return combined `ping`/`nslookup` output as before.
