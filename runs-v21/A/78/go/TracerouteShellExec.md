## Verdict

OS Command Injection vulnerability confirmed. User-controlled input from the HTTP request query parameter is directly interpolated into a shell command string and executed via `sh -c`, allowing arbitrary command execution.

## Source

Line 16 constructs a shell command by string interpolation:
```
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
```

Line 18 executes it through a shell:
```
cmd := exec.Command("sh", "-c", cmdLine)
```

The `host` parameter originates from untrusted user input (line 10) with no validation or escaping, enabling command injection through shell metacharacters.

## Fix

### File: TracerouteShellExec.go

```go
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

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

func main() {
	http.HandleFunc("/traceroute", tracerouteHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The vulnerability is eliminated by passing the program and its arguments as separate parameters to `exec.Command()` instead of constructing a single shell command string. Go's `exec.Command()` automatically treats each argument as a literal value when invoked without a shell, preventing the shell from interpreting metacharacters in the `host` parameter. This approach is both simpler and more secure than attempting to escape special characters, as it closes the injection sink entirely rather than requiring caller discipline for quoting or escaping.
