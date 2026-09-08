## Verdict

The code is vulnerable to path traversal. The `name` parameter from the URL query is used in `filepath.Join()` without validation, allowing an attacker to supply path traversal sequences like `../../../etc/passwd` to escape the intended `docsRoot` directory and read arbitrary files.

## Source

**File:** FilepathJoinUserInput.go  
**Line:** 18-21

The vulnerability exists because:
- Line 12: `name` comes from untrusted user input via `r.URL.Query().Get("file")`
- Line 18: `filepath.Join(docsRoot, name)` is called without validating the result
- Line 21: `os.ReadFile(path)` uses the potentially escaped path

When `name` contains `..` sequences, `filepath.Join()` normalizes them, allowing navigation outside `docsRoot`. For example, `filepath.Join("/var/app/docs", "../../../etc/passwd")` resolves to `/etc/passwd`.

## Fix

### File: FilepathJoinUserInput.go

```go
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const docsRoot = "/var/app/docs"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	path := filepath.Join(docsRoot, name)
	cleanPath := filepath.Clean(path)
	cleanDocsRoot := filepath.Clean(docsRoot)

	// Ensure the resolved path is within docsRoot
	if !strings.HasPrefix(cleanPath, cleanDocsRoot+string(filepath.Separator)) && cleanPath != cleanDocsRoot {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
```

## Explanation

The fix adds a containment check that validates the resolved path stays within the intended `docsRoot` directory:

1. **Normalize paths:** `filepath.Clean()` resolves `..` sequences and normalizes the path to a canonical form
2. **Containment validation:** Compare the cleaned target path against the cleaned base directory using `strings.HasPrefix()` with proper path separator handling
3. **Reject escapes:** If the path does not start with `docsRoot/` (and is not exactly `docsRoot`), reject it with HTTP 403 Forbidden

The check must verify that `cleanPath` starts with `cleanDocsRoot + "/" ` (not just `cleanDocsRoot` alone) to prevent a sibling directory attack where `docsRoot = "/var/app/docs"` but an attacker could access `/var/app/docsspoof`.

By using `filepath.Clean()` before the check, we ensure that attacks using `..` or other normalization tricks are caught by the containment validation. The `os.ReadFile()` call then uses the validated `cleanPath` instead of the raw joined path.
