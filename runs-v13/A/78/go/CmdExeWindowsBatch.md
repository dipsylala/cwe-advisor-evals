## Verdict

**Confirmed**: OS command injection via unvalidated user input concatenated into a Windows batch command string.

## Source

Line 28 in `diagnostics.go` executes a batch command constructed from user-supplied input:

```go
target := r.URL.Query().Get("target")  // Line 16: unconstrained user input
batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)  // Line 25: direct concatenation
cmd := exec.Command("cmd", "/C", batchLine)  // Line 28: passed to shell interpreter
```

The `target` query parameter is read directly from the HTTP request without validation, then interpolated into a batch command line that is executed via `cmd.exe /C`. An attacker can inject arbitrary Windows batch commands by supplying shell metacharacters in the target parameter (e.g., `&`, `|`, `>`, `%`).

## Fix

Validate `target` against a strict whitelist pattern before use. Accept only characters valid in a hostname or dotted-decimal IPv4 address:

```go
func diagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Validate target is a valid hostname or IPv4 address.
	// Allow alphanumeric, dots, and hyphens only.
	if !regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`).MatchString(target) {
		http.Error(w, "invalid target format", http.StatusBadRequest)
		return
	}

	batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)
	cmd := exec.Command("cmd", "/C", batchLine)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "diagnostic command failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}
```

Add `import "regexp"` at the top of the file.

## Explanation

The attack surface is the `target` parameter: an attacker controls its value via the query string. Concatenating it directly into a batch command line allows injection of batch metacharacters (`&`, `|`, `>`, etc.) that alter the command's meaning and let arbitrary code execute.

The fix restricts `target` to a character set safe in both hostname and IP address contexts: letters, digits, dots, and hyphens. This prevents injection of any batch metacharacters. The validation rejects the request if the target format is invalid, failing closed rather than attempting a potentially dangerous sanitization that could be bypassed.

Alternative mitigations (not used here because whitelist validation is simpler and safer):
- Escaping all batch metacharacters with `^` (error-prone and fragile)
- Using `exec.Command()` argument arrays for the ping and nslookup commands separately (would require parsing the batch language, or redesigning the diagnostic tool)

The whitelist approach is preferred because it eliminates the attack surface entirely—a character that cannot appear in the input cannot be injected, regardless of where the input is used.
