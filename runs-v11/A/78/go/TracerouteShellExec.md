## Verdict
Real vulnerability. User-supplied `host` from the query parameter is interpolated unsanitized into a shell command string and executed, allowing command injection.

## Source
Line 10 retrieves untrusted input: `host := r.URL.Query().Get("host")`

Line 16 constructs a shell command with unsanitized input:
```
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
```

Line 18 executes the command via shell interpreter:
```
cmd := exec.Command("sh", "-c", cmdLine)
```

An attacker can inject arbitrary shell metacharacters. For example, a request with `?host=example.com;%20rm%20-rf%20/` would execute both `traceroute` and `rm`.

## Fix
Pass `traceroute` and its arguments directly to `exec.Command()` without a shell. Remove the shell string construction and pass arguments as separate slices:

```go
func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("traceroute", "-m", "15", host)

	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "traceroute failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}
```

## Explanation
Using `exec.Command()` with separate argument strings bypasses the shell interpreter entirely. Shell metacharacters like `;`, `|`, `&`, `$()`, and backticks are treated as literal characters, not control operators. This prevents injection.

The fixed code passes `"traceroute"`, `"-m"`, `"15"`, and the untrusted `host` as distinct arguments. Each argument is passed directly to the `traceroute` binary without shell parsing, making it impossible to break out of the intended command.
