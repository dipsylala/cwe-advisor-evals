## Verdict

**Confirmed.** The code accepts arbitrary filenames from user-provided `header.Filename` without validating file type or extension. An attacker can upload executable, script, or other dangerous file types and store them in the application directory where they may be executed or served as dangerous content.

## Source

`avatar_upload.go:27` — `os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)`

The sink is `os.WriteFile()`. The source is `header.Filename` from the HTTP multipart form file header, provided by the user in the upload request.

## Fix

```go
package avatars

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
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

	// Validate MIME type
	if !strings.HasPrefix(header.Header.Get("Content-Type"), "image/") {
		http.Error(w, "invalid file type", http.StatusBadRequest)
		return
	}

	// Extract and validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExtensions[ext] {
		http.Error(w, "invalid file extension", http.StatusBadRequest)
		return
	}

	// Generate safe filename using UUID
	safeFilename := uuid.New().String() + ext
	err = os.WriteFile(filepath.Join(storageDir, safeFilename), bytes, 0o600)
	if err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

The vulnerability stems from accepting the user-supplied `header.Filename` directly without validation. An attacker could upload a file named `shell.php` or `exploit.html` and have it executed or served by the web server, leading to arbitrary code execution or content injection.

The fix enforces a whitelist of safe image file extensions (`.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`) and validates the MIME type prefix. Most critically, the uploaded file is saved with a generated filename (using UUID + validated extension) instead of the user-provided name, preventing attackers from controlling the filename stored on disk.

This approach:
1. **Validates MIME type** — rejects uploads claiming to be non-image types
2. **Whitelists extensions** — only `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp` are accepted
3. **Generates safe filenames** — prevents directory traversal and dangerous filenames; the user's original filename is discarded
4. **Prevents execution** — even if a malicious file bypasses checks, it is renamed to an image extension and cannot execute as a script

The UUID filename also decouples the filename used for storage from the filename used for retrieval, so the calling code in `avatar_lookup.go` must be updated to store and use the generated filename rather than the original user-provided filename.
