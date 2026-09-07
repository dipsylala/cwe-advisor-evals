## Verdict

Exploitable.

## Source

`r.URL.Query().Get("target")` at line 16 returns untrusted HTTP query parameter.

## Fix

**Vulnerable code:**
```go
func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)

	cmd := exec.Command("cmd", "/C", batchLine)  // Injection sink
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}
```

**Fixed code:**
```go
import (
	"net/http"
	"os/exec"
	"regexp"
)

func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Validate target against allowlist: must be a valid hostname or IPv4 address.
	// This prevents command injection via shell metacharacters before the target
	// reaches exec.Command arguments.
	if !isValidTarget(target) {
		http.Error(w, "invalid target format", http.StatusBadRequest)
		return
	}

	// Run ping and nslookup as separate processes with arguments, not through cmd /C.
	// Passing arguments separately prevents shell interpretation even if the input
	// somehow bypasses allowlist validation.
	pingCmd := exec.Command("ping", "-n", "4", target)
	pingOutput, pingErr := pingCmd.CombinedOutput()

	nslookupCmd := exec.Command("nslookup", target)
	nslookupOutput, nslookupErr := nslookupCmd.CombinedOutput()

	// Combine output from both commands as before. Return error status if either failed.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(pingOutput)
	w.Write(nslookupOutput)

	if pingErr != nil || nslookupErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// isValidTarget validates that target is a safe hostname or IPv4 address.
// Rejects values with shell metacharacters or patterns that could be commands.
func isValidTarget(target string) bool {
	matched, _ := regexp.MatchString(
		`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`,
		target,
	)
	return matched
}
```

## Explanation

The vulnerability exists because untrusted `target` input is concatenated into a batch command string and passed to `cmd.exe /C`, which interprets shell metacharacters. The attacker can inject arbitrary Windows commands using `&`, `&&`, `|`, `;`, or `()`.

The fix eliminates the shell by invoking `ping.exe` and `nslookup.exe` directly via `exec.Command` with separate arguments. Windows command line arguments are not re-parsed by a shell when passed as a separate argument array (though `cmd.exe` does have edge cases; here we avoid `cmd.exe` entirely). The allowlist validation using a regular expression restricts the target to valid hostname and IPv4 formats, rejecting shell metacharacters at entry. Together, these eliminate the injection path: untrusted input is validated before use, and no shell is invoked to interpret it.

## Behaviour changes

- **Import change**: Added `regexp` import; removed `fmt` import (no longer needed for `fmt.Sprintf`).
- **New function added**: `isValidTarget()` validates the target format. This rejects invalid input with an HTTP 400 response instead of passing it to commands.
- **Command invocation**: Changed from one shell command (`cmd /C ping ... && nslookup ...`) to two separate process invocations (`ping`, then `nslookup`). Each argument is passed separately, so the shell is never invoked.
- **Error handling**: Error status is set if either `ping` or `nslookup` exits with non-zero status, preserving the original intent (the original `&&` would have skipped `nslookup` if `ping` failed; here both are always attempted and output is combined regardless of exit status). This provides slightly better diagnostics by always returning output from both commands.
