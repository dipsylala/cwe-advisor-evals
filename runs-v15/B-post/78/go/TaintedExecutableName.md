## Verdict

Exploitable. The `tool` parameter is derived directly from untrusted HTTP query input (`r.URL.Query().Get("tool")`) and passed to `exec.Command()` as the executable name without validation, allowing arbitrary command execution.

## Source

HTTP query parameter `tool` from `r.URL.Query().Get("tool")` on line 13, passed to `runDiagnostic()` on line 21.

## Fix

**Vulnerable code:**

```go
// runDiagnostic shells out to the requested diagnostic utility and
// returns its combined output.
func runDiagnostic(tool, target string) ([]byte, error) {
	// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

**Fixed code:**

```go
// Allowed diagnostic tools that can be safely executed
var allowedTools = map[string]bool{
	"ping":       true,
	"traceroute": true,
	"dig":        true,
	"nslookup":   true,
	"host":       true,
}

// runDiagnostic shells out to the requested diagnostic utility and
// returns its combined output.
func runDiagnostic(tool, target string) ([]byte, error) {
	// Validate tool against allowlist to prevent command injection
	if !allowedTools[tool] {
		return nil, fmt.Errorf("unsupported tool: %q", tool)
	}
	
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation

The fix adds an allowlist of approved diagnostic tools and validates the `tool` parameter against it before passing it to `exec.Command()`. Because the command execution is the intended purpose of this endpoint (not incidental), elimination is not an option; instead, allowlist validation enforces that only known-safe utilities can be executed. The validation uses a map lookup (more efficient than a slice iteration) and rejects the request with a clear error message for any tool not on the list. Using the allowlist-approved value (already present in the map key) downstream eliminates the injection point: the attacker can no longer control which executable runs, only whether their request is rejected.

## Behaviour changes

The handler now rejects requests with tool values not in the allowlist, returning an error response instead of attempting execution. This is intentional: the handler's contract was to run one of a "handful of network diagnostic utilities," so rejection of unsupported tools is correct behaviour, not a regression. The return value contract (`([]byte, error)`) and output handling remain unchanged. Callers that were relying on arbitrary tool execution will see failures with tool names outside the allowlist, but no legitimate callers of the intended interface should be affected since only pre-approved utilities were supported.
