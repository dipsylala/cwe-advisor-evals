## Verdict
exploitable

## Source
HTTP query parameter `tool` (line 13: `r.URL.Query().Get("tool")`)

## Fix

**Vulnerable code:**
```go
func runDiagnostic(tool, target string) ([]byte, error) {
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

**Fixed code:**
```go
// Define allowlist of permitted diagnostic tools
var allowedTools = map[string]string{
	"ping":       "ping",
	"traceroute": "traceroute",
	"nslookup":   "nslookup",
	"dig":        "dig",
}

func runDiagnostic(tool, target string) ([]byte, error) {
	// Validate tool against allowlist
	approvedTool, ok := allowedTools[tool]
	if !ok {
		return nil, fmt.Errorf("tool %q is not permitted", tool)
	}
	
	cmd := exec.Command(approvedTool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation
The vulnerability exists because the `tool` parameter is read directly from untrusted user input (HTTP query string) and passed to `exec.Command()` as the executable name without validation. This allows an attacker to execute arbitrary programs by supplying values like `../../../bin/sh` or known binaries like `nc`. The fix implements a strict allowlist that maps user-supplied tool names to specific approved diagnostic binaries. Only after validating the input against this allowlist is the approved tool name passed to `exec.Command()`. The fix uses a map lookup to break taint—the original tainted string is validated but never used downstream; only the allowlist-approved value is supplied to the sink. This prevents command injection while preserving the original functionality: returning the combined output of the approved diagnostic tool.

## Behaviour changes
none
