## Verdict

Real vulnerability. The `host` parameter from the HTTP request is concatenated into a command string without validation and executed through `sh -c`, enabling OS command injection via shell metacharacters.

## Source

`host` parameter at line 10: `r.URL.Query().Get("host")` - untrusted attacker-controlled data from HTTP query string.

## Fix

**Vulnerable code (line 16-18):**
```go
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
cmd := exec.Command("sh", "-c", cmdLine)
```

**Fixed code:**
```go
import (
	"context"
	"net"
	"time"
)

// Validate host: reject values starting with dash and verify it's a valid hostname or IP
if len(host) == 0 || host[0] == '-' {
	http.Error(w, "invalid host parameter", http.StatusBadRequest)
	return
}

if net.ParseIP(host) == nil {
	_, err := net.LookupHost(host)
	if err != nil {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}
}

// Use exec.Command without shell, passing host as separate argument
ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
defer cancel()

cmd := exec.CommandContext(ctx, "traceroute", "-m", "15", host)
output, err := cmd.CombinedOutput()
```

## Explanation

The fix eliminates shell invocation by passing `traceroute` and its arguments directly to `exec.CommandContext` as separate parameters rather than concatenating them into a single string for `sh -c` to parse. The shell never interprets the `host` value, so shell metacharacters are treated as literal data. Validation prevents argument injection (CWE-88) by rejecting values starting with `-` and confirming the host is resolvable as a valid IP or hostname. `exec.CommandContext` with a 30-second timeout adds robustness by bounding execution time. The fix preserves the original behaviour: `CombinedOutput()` still returns stdout and stderr combined, and error handling remains unchanged.

## Behaviour changes

- Command execution no longer uses a shell
- Invalid host values (empty, starting with `-`, or unresolvable) now return HTTP 400 instead of attempting execution
- Command execution is bounded by a 30-second timeout; requests exceeding it will fail
- Shell metacharacters in the host parameter are now treated as literal characters, not command syntax
