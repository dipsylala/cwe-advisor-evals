## Verdict

Exploitable

## Source

HTTP query parameter `target` (line 16: `r.URL.Query().Get("target")`), passed unsanitized into the command string.

## Fix

**Vulnerable Code**
```go
target := r.URL.Query().Get("target")
if target == "" {
    http.Error(w, "target query parameter is required", http.StatusBadRequest)
    return
}

batchLine := fmt.Sprintf("ping -n 4 %s && nslookup %s", target, target)

cmd := exec.Command("cmd", "/C", batchLine)
output, err := cmd.CombinedOutput()
```

**Fixed Code**
```go
target := r.URL.Query().Get("target")
if target == "" {
    http.Error(w, "target query parameter is required", http.StatusBadRequest)
    return
}

// Validate target against a strict allowlist to prevent command injection.
// Allow IPv4, IPv6, and valid hostnames (alphanumeric, hyphens, dots only).
targetPattern := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$|^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[?(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?$`)
if !targetPattern.MatchString(target) {
    http.Error(w, "invalid target format", http.StatusBadRequest)
    return
}

var output bytes.Buffer

// Run ping with target as a separate argument, not a shell string.
pingCmd := exec.Command("ping", "-n", "4", target)
pingOut, err := pingCmd.CombinedOutput()
if err != nil {
    http.Error(w, "ping command failed: "+err.Error(), http.StatusInternalServerError)
    return
}
output.Write(pingOut)
output.WriteString("\n")

// Run nslookup with target as a separate argument.
nslookupCmd := exec.Command("nslookup", target)
nslookupOut, err := nslookupCmd.CombinedOutput()
if err != nil {
    http.Error(w, "nslookup command failed: "+err.Error(), http.StatusInternalServerError)
    return
}
output.Write(nslookupOut)

w.Header().Set("Content-Type", "text/plain; charset=utf-8")
w.Write(output.Bytes())
```

Add `"regexp"` and `"bytes"` to imports:
```go
import (
    "bytes"
    "fmt"
    "net/http"
    "os/exec"
    "regexp"
)
```

## Explanation

The original code concatenated user input directly into a shell command string passed to `cmd.exe`, allowing injection via shell metacharacters (`;`, `&&`, `||`, `$()`, etc.). The fix eliminates shell interpretation entirely by invoking `ping` and `nslookup` directly as separate `exec.Command` calls, with the target passed as a distinct argument. A strict allowlist regex validates the target format (hostname or IP address patterns only), rejecting values with leading hyphens or other shell metacharacters. The validated allowlist check happens before the values reach any exec sink, preventing downstream re-interpretation. The fix preserves the original behavior: it returns the combined output of both commands to the HTTP response exactly as before.

## Behaviour changes

- Replaced shell-based command construction (`cmd /C`) with direct executable invocation, which prevents interpretation of shell metacharacters in arguments.
- Added input validation via allowlist regex before command execution, reducing the attack surface.
- Split the single combined shell command into two separate `exec.Command` calls to `ping` and `nslookup`, which requires explicit handling to combine their outputs via `bytes.Buffer`.
- Added a newline separator between ping and nslookup output for clarity (original bash-style `&&` did not add spacing).
- Added `regexp` and `bytes` imports to support validation and output buffering.

All changes preserve the sink contract: combined stdout/stderr from both diagnostic commands is returned to the HTTP response on success, and errors are reported to the response with appropriate HTTP status codes.
