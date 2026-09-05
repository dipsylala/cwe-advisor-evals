## Verdict

The vulnerability is confirmed. Line 27 of `avatar_upload.go` uses user-supplied `header.Filename` directly as a file path without validating the file type or sanitizing the filename. This allows an attacker to upload files with dangerous extensions or path traversal sequences.

## Source

The vulnerability exists at line 27 in `avatar_upload.go`:

```go
os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)
```

The filename comes directly from the user-supplied HTTP request header without any validation. Combined with `avatar_lookup.go` line 9, which reads files back using the same unsanitized filename, an attacker can:
- Upload executable files with dangerous extensions
- Use path traversal sequences in the filename (e.g., `../../etc/passwd`) to write outside the intended directory
- Overwrite existing files

## Fix

```go
package avatars

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const storageDir = "/var/app-data/avatars"

var allowedExtensions = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
	".webp": true,
}

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

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExtensions[ext] {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Generate a safe random filename to prevent path traversal and overwrite attacks
	randomName := make([]byte, 16)
	_, err = rand.Read(randomName)
	if err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	safeFilename := fmt.Sprintf("%x%s", randomName, ext)

	err = os.WriteFile(filepath.Join(storageDir, safeFilename), bytes, 0o600)
	if err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

The fix implements three layers of defense:

1. **Extension Allowlist**: Only image file types (`.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`) are permitted. Any other extension is rejected before the file is written, preventing upload of executable or script files.

2. **Filename Sanitization via Randomization**: Instead of trusting the user-supplied filename, the code generates a cryptographically random filename using `crypto/rand`. This eliminates:
   - Path traversal attacks using sequences like `../` or absolute paths
   - Filename collisions and intentional overwrites
   - Predictable file naming that could be exploited

3. **Extension Preservation**: The original file extension is appended to the random name to maintain file type information, allowing the application to serve the file correctly (e.g., with the right MIME type).

This approach ensures that only expected file types are uploaded and that filesystem operations remain confined to the designated storage directory, regardless of what filename an attacker supplies.
