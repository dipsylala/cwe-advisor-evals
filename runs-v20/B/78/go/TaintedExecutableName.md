## Verdict

exploitable (confidence: high)

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- Location: `diagnostics.go`, line 35 (sink), inside `runDiagnostic`

## Source

- Source: the `tool` and `target` query parameters read from the incoming request in `DiagnosticsHandler` via `r.URL.Query().Get("tool")` / `r.URL.Query().Get("target")` (lines 13-14).
- Flow: both values pass unmodified as parameters into `runDiagnostic(tool, target)` (line 21), with only an empty-string check (line 16) - no validation of content.
- Sink: `exec.Command(tool, "-c", "4", target)` (line 35). `tool` is used as the **executable path itself**, not just an argument - a caller can name any program on the host (or an absolute path to one) and it will be launched with attacker-influenced arguments. `target` additionally reaches the sink as a bare positional argument, so a value starting with `-` could be read as a flag by whatever program `tool` resolves to.

This is a more severe variant of command injection than string-concatenation into a shell: no shell is invoked, but the program to execute is fully attacker-controlled, giving arbitrary code execution equivalent to running any binary reachable on the host.

## Fix

### File: diagnostics.go

```go
package diagnostics

import (
	"fmt"
	"net/http"
	"os/exec"
)

// allowedDiagnosticTools maps the "tool" query value a caller may request
// to the absolute path of the diagnostic executable it runs. The tool
// name coming from the request is looked up here and never passed to
// exec.Command directly, so a request can only ever launch one of these
// known binaries. Assumes a Linux deployment; adjust the path if ping
// lives elsewhere on the target host.
var allowedDiagnosticTools = map[string]string{
	"ping": "/usr/bin/ping",
}

// DiagnosticsHandler lets an on-call engineer run one of a handful of
// network diagnostic utilities against a target host from the ops
// dashboard, e.g. GET /diagnostics/run?tool=ping&target=10.0.0.5
func DiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	target := r.URL.Query().Get("target")

	if tool == "" || target == "" {
		http.Error(w, "tool and target query parameters are required", http.StatusBadRequest)
		return
	}

	output, err := runDiagnostic(tool, target)
	if err != nil {
		http.Error(w, fmt.Sprintf("diagnostic failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// runDiagnostic shells out to the requested diagnostic utility and
// returns its combined output.
func runDiagnostic(tool, target string) ([]byte, error) {
	path, ok := allowedDiagnosticTools[tool]
	if !ok {
		return nil, fmt.Errorf("unsupported diagnostic tool: %q", tool)
	}

	// "--" stops the utility's own option parsing so target can never be
	// read as a flag, even if it starts with "-".
	cmd := exec.Command(path, "-c", "4", "--", target)
	return cmd.CombinedOutput()
}
```

## Explanation

The vulnerability was that `tool` - fully attacker-controlled - was passed straight into `exec.Command` as the program to execute, so a request could launch any binary reachable on the host rather than one of the intended diagnostic utilities. The fix introduces `allowedDiagnosticTools`, a map the application owns from a known tool identifier to the absolute path of the one utility that identifier is allowed to run (`ping` -> `/usr/bin/ping`). `runDiagnostic` looks the requested `tool` value up in this map and uses the resolved, trusted path as the executable; the raw request value is never passed to `exec.Command`. An unrecognized `tool` is rejected before any process is spawned. This also satisfies the guidance's absolute-path recommendation, closing the separate `PATH`-substitution risk. Because `target` still reaches the sink as its own `exec.Command` argument (no shell is invoked either before or after the fix), a literal `--` is inserted ahead of it so the target utility cannot interpret a `target` value starting with `-` as one of its own flags (CWE-88); this rejects no legitimate target values. `target` itself is not pattern-validated, since the application does not own or constrain the format of a diagnostic target host.

Verification: the fixed file was copied to a standalone scratch module and checked with `gofmt -l` (no formatting issues) and `go vet ./...` plus `go build ./...` (both completed with no diagnostics), confirming the file compiles and is free of vet warnings. No test suite was available in the case directory to exercise against.

## Behaviour changes

- Executable resolution changed from "whatever string the request supplies" to "one of a fixed, code-owned map of known diagnostic tools resolved to an absolute path." This is the core fix for the CWE-78 finding, not incidental.
- A `tool` value outside the allowlist now fails with `unsupported diagnostic tool: "<value>"` before any process is spawned, surfaced through the same existing `500 diagnostic failed: ...` error path the handler already used for any `runDiagnostic` failure. Previously, an unrecognized tool name would in most cases have failed anyway when the OS could not find/execute that program (also surfacing as the same 500 response), or, in the worst case, have executed an arbitrary attacker-chosen binary; the response shape for the caller is unchanged, only the failure now happens earlier and for a well-defined reason.
- A literal `--` argument is now inserted between the fixed `"-c" "4"` flags and `target`. This is additive positional-argument-terminator syntax that `ping` (getopt-based option parsing) treats as "end of options" and does not change how a normal target (a hostname or IP) is interpreted; it only forecloses a `target` value such as `-o` or `--argument` being read as a flag by `ping`. `cmd.CombinedOutput()`'s return value, and everything the handler does with it, is unchanged.
- Only `ping` is included in the allowlist. The handler's own doc comment names `ping` as its sole concrete example; the comment's "a handful of ... utilities" wording suggests more may be intended, but nothing in the source identifies which others or what arguments they take, so adding entries for unnamed tools would be a guess rather than a verified fix. Extending `allowedDiagnosticTools` to cover any additional intended tools (with their correct absolute paths and flag conventions) is a follow-up for whoever owns that list, not something inferable from this file - noted as an assumption, lowering confidence on completeness of the tool set (not on the fix's correctness for the injection itself).
- No change to imports beyond none added; `os/exec` and `fmt` were already imported and are reused for the map lookup error and unchanged `exec.Command` call.
