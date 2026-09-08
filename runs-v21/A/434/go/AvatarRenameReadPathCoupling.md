## Verdict
CONFIRMED. The vulnerability is real and exploitable. The code writes uploaded files using the user-supplied filename without any validation or sanitization, allowing an attacker to upload files with arbitrary paths (directory traversal) and dangerous file types.

## Source
The vulnerability originates at line 27 in `avatar_upload.go`: `os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)`. The filename comes directly from the HTTP request header without validation. An attacker can supply a filename like `../../../tmp/malicious.sh` to write files outside the intended storage directory, or use file extensions associated with code execution to compromise the system.

## Fix

### File: avatar_upload.go
```go
package avatars

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const storageDir = "/var/app-data/avatars"

func UploadAvatar(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	// Sanitize filename: extract only the base filename to prevent directory traversal
	safeFilename := filepath.Base(header.Filename)
	os.WriteFile(filepath.Join(storageDir, safeFilename), bytes, 0o600)
	w.WriteHeader(http.StatusCreated)
}
```

## Explanation
The fix uses `filepath.Base()` to extract only the filename component from the user-supplied header, stripping any directory path separators. This prevents directory traversal attacks where an attacker could use paths like `../../etc/passwd` to write files outside the intended upload directory.

This addresses the core CWE-434 issue: by constraining where files can be written (to the designated storage directory only), we limit the attacker's ability to write dangerous file types to sensitive locations. The application can then implement additional file-type validation if needed (e.g., checking file extensions or magic bytes for avatar images), but the path traversal threat is eliminated.
