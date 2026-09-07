## Verdict

**CONFIRMED** - OS Command Injection via shell invocation with untrusted string concatenation.

The code constructs a command string using `fmt.Sprintf("traceroute -m 15 %s", host)` where `host` is untrusted input from an HTTP query parameter, then passes it to `exec.Command("sh", "-c", cmdLine)`. This allows arbitrary shell commands to be injected through the `host` parameter via special characters like `;`, `|`, `&&`, `$()`, and backticks.

## Source

**File:** `TracerouteShellExec.go`  
**Line:** 18 (sink); data flow from line 10 (source) through line 16 (transformation)

Data flow:
1. **Source** (line 10): `host := r.URL.Query().Get("host")` - untrusted HTTP query parameter
2. **Transformation** (line 16): `cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)` - string concatenation builds command string with untrusted input
3. **Sink** (line 18): `cmd := exec.Command("sh", "-c", cmdLine)` - shell invocation executes the tainted command string

The vulnerability is exploitable because the shell interpreter (`sh -c`) is explicitly requested, and the command line is constructed via string concatenation with untrusted input. An attacker controlling the `host` parameter can inject shell metacharacters to execute arbitrary commands.

Example exploit: `host=localhost; rm -rf /` would execute the injected `rm` command after traceroute.

## Fix

### File: TracerouteShellExec.go

```go
package main

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	// Validate host is a valid hostname or IP address
	// Reject values starting with - to prevent flag injection
	if strings.HasPrefix(host, "-") {
		http.Error(w, "invalid host parameter", http.StatusBadRequest)
		return
	}

	// Verify host is a valid IP or hostname
	ip := net.ParseIP(host)
	if ip == nil {
		// Not a valid IP; check if it's a valid hostname
		// Hostnames must contain only alphanumerics, dots, and hyphens
		valid := true
		for _, c := range host {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			     (c >= '0' && c <= '9') || c == '.' || c == '-') {
				valid = false
				break
			}
		}
		if !valid {
			http.Error(w, "invalid host parameter", http.StatusBadRequest)
			return
		}
	}

	// Use exec.Command with separate arguments, no shell
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "traceroute", "-m", "15", host)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "traceroute failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

func main() {
	http.HandleFunc("/traceroute", tracerouteHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix eliminates the OS Command Injection vulnerability by applying three key changes:

1. **Eliminate shell invocation**: Changed from `exec.Command("sh", "-c", cmdLine)` to `exec.CommandContext(ctx, "traceroute", "-m", "15", host)`. Removing the shell interpreter (`"sh"` and `"-c"`) prevents the shell from parsing metacharacters in the input. The separate argument list means arguments are passed directly to the `traceroute` binary without shell re-parsing.

2. **Input validation**: Added validation to ensure the `host` parameter conforms to the application's expected format (valid IP address or hostname). The validation rejects:
   - Values starting with `-` (prevents flag injection where `traceroute` might misinterpret the value as an option)
   - Hostnames containing characters other than alphanumerics, dots, and hyphens (prevents shell escape sequences)

3. **Defense-in-depth hardening**: Added `exec.CommandContext` with a 30-second timeout to bound any unavoidable process execution, protecting against slowloris and resource exhaustion attacks.

The fix preserves the original behavior: it still returns the output of the `traceroute` command via `CombinedOutput()` and sends it to the HTTP response with the correct content type. The syntax changes align with Go's standard library best practices for safe command execution.

## Behaviour changes

**Input behavior (stricter):**
- The handler now validates that `host` is a valid IP address or a hostname containing only alphanumerics, dots, and hyphens
- Requests with invalid hosts (e.g., containing spaces, quotes, semicolons, pipes, or starting with `-`) are rejected with HTTP 400 Bad Request
- This prevents shell metacharacter injection and flag injection, but blocks hosts with internationalized domain names (IDNs), underscores in subdomains, or other non-ASCII characters

**Output behavior (preserved):**
- The response body and content type remain unchanged: the combined stdout/stderr output of the `traceroute` command as plain text
- Error handling is preserved: failed execution still returns HTTP 500

**Execution behavior (improved):**
- Process execution is now bounded by a 30-second timeout, preventing indefinite hangs
- Removed shell parsing overhead and interpreter invocation
- The `traceroute` binary receives arguments directly, not re-parsed by a shell
