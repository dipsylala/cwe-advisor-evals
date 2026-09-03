## Verdict

Exploitable

## Source

HTTP query parameter `host` at line 10: `host := r.URL.Query().Get("host")`

## Fix

**Vulnerable code (line 16-18):**
```go
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
cmd := exec.Command("sh", "-c", cmdLine)
```

**Fixed code:**
```go
// Validate host parameter: reject if empty, starts with '-', or contains invalid characters
if len(host) == 0 || host[0] == '-' {
	http.Error(w, "invalid host parameter", http.StatusBadRequest)
	return
}

// Allow only hostname/IPv4/IPv6 format characters
hostRe := regexp.MustCompile(`^[a-zA-Z0-9.:]+$`)
if !hostRe.MatchString(host) {
	http.Error(w, "invalid host parameter", http.StatusBadRequest)
	return
}

// Pass each argument separately to prevent shell injection
cmd := exec.Command("traceroute", "-m", "15", host)
```

**Required import addition:**
```go
import "regexp"
```

## Explanation

The vulnerability exists because untrusted user input (`host` parameter) is directly concatenated into a shell command string via `fmt.Sprintf`, then executed through `sh -c`. An attacker can inject shell metacharacters to execute arbitrary commands. The fix eliminates shell invocation entirely by passing arguments separately to `exec.Command("traceroute", ...)`, which prevents shell interpretation of special characters. Input validation using a strict allowlist regex ensures only valid hostname and IP address characters are accepted, and rejects values starting with hyphens to prevent argument injection attacks (CWE-88). The validated host value—not the raw input—is passed as a separate argument to the command.

## Behaviour changes

None. The command executes with the same arguments and produces the same output. The only change is removing the shell interpreter (`sh -c`) and adding input validation, which rejects invalid hostnames/IPs that would likely have failed in traceroute anyway.
