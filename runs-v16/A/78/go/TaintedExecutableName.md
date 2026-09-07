## Verdict

The `tool` parameter from user input is used directly as the executable name in `exec.Command()`. Although Go does not perform shell-metacharacter expansion on the program name, this allows an attacker to invoke any executable on the system or reference arbitrary paths, enabling arbitrary command execution.

## Source

```go
func DiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	target := r.URL.Query().Get("target")
	// ...
	output, err := runDiagnostic(tool, target)
}

func runDiagnostic(tool, target string) ([]byte, error) {
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Fix

Use an allowlist of permitted diagnostic tools and validate the `tool` parameter against it:

```go
var allowedTools = map[string]bool{
	"ping":      true,
	"traceroute": true,
	"nslookup":  true,
}

func DiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	target := r.URL.Query().Get("target")

	if tool == "" || target == "" {
		http.Error(w, "tool and target query parameters are required", http.StatusBadRequest)
		return
	}

	if !allowedTools[tool] {
		http.Error(w, "invalid tool", http.StatusBadRequest)
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

func runDiagnostic(tool, target string) ([]byte, error) {
	cmd := exec.Command(tool, "-c", "4", target)
	return cmd.CombinedOutput()
}
```

## Explanation

The vulnerability occurs because `tool` is sourced from an untrusted HTTP query parameter and passed directly to `exec.Command()`. Although `exec.Command()` does not interpret shell metacharacters, the program name itself can be used to reference any executable path on the system.

The fix validates the `tool` parameter against an allowlist of permitted diagnostic utilities before passing it to `exec.Command()`. This ensures only intended tools (e.g., `ping`, `traceroute`, `nslookup`) can be executed, preventing an attacker from invoking arbitrary programs or malicious scripts on the system. The allowlist check replaces the overly permissive design with an explicit permit policy appropriate for an operations dashboard that should provide only a narrow set of diagnostic capabilities.
