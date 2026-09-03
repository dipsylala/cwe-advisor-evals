## Verdict
exploitable

## Source
The `tool` query parameter is extracted from untrusted HTTP request input at line 13 (`r.URL.Query().Get("tool")`) and passed directly to `exec.Command()` at line 35 without validation. An attacker can supply any executable name or path, including absolute paths to alternate system utilities or scripts not intended to be accessible through this endpoint.

## Fix

**Vulnerable Code:**
```go
func runDiagnostic(tool, target string) ([]byte, error) {
	// SAST FINDING: CWE-78 - tool is untrusted user input
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

**Fixed Code:**
```go
var diagnosticTools = map[string]string{
	"ping":       "/bin/ping",
	"traceroute": "/bin/traceroute",
	"dig":        "/usr/bin/dig",
	"nslookup":   "/usr/bin/nslookup",
}

func runDiagnostic(tool, target string) ([]byte, error) {
	// Validate tool against allowlist before execution
	toolPath, ok := diagnosticTools[tool]
	if !ok {
		return nil, fmt.Errorf("unknown diagnostic tool: %s", tool)
	}
	
	cmd := exec.Command(toolPath, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation
The original code passes the untrusted `tool` parameter directly as the executable name to `exec.Command()`. Although `exec.Command()` with separate arguments prevents shell metacharacter injection, it does not validate the executable name itself—an attacker can supply any binary name or absolute path. The fix introduces a static allowlist mapping user-provided tool names to their absolute executable paths. Only values present in the allowlist are permitted; the raw input is never used in `exec.Command()`. The allowed paths use absolute paths to avoid `PATH`-based substitution attacks. Attempting to run a tool not in the allowlist returns an error instead of executing an attacker-chosen binary, closing the injection point entirely.

## Behaviour changes
Added a static allowlist check that restricts executable invocation to pre-approved diagnostic tools. The endpoint now returns an error with message "unknown diagnostic tool: {tool}" when the tool parameter does not match an allowlisted entry, where previously it would attempt to execute the supplied name. This is a tighter security posture but changes the error response for invalid tool names. The allowlist should be populated with the set of diagnostic utilities actually intended to be exposed through this endpoint.
