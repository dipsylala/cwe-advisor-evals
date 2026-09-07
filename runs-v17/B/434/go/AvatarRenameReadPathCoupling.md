## Verdict

EXPLOITABLE. The finding is valid. Line 27 writes uploaded files to disk using the client-supplied filename directly, without validating file type or protecting against path traversal. An attacker can upload files with malicious extensions (e.g., `.php`, `.exe`, `.bat`) or path traversal sequences (e.g., `../../../etc/passwd`). Since `ReadAvatarBytes` in `avatar_lookup.go` retrieves files by the original filename, the attacker can later retrieve and execute malicious files if the storage directory is served by a web server or accessible through the application.

## Source

`header.Filename` from `r.FormFile("avatar")` in the multipart form - client-supplied, untrusted metadata from the HTTP request.

## Fix

### File: avatar_upload.go

```go
package avatars

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const storageDir = "/var/app-data/avatars"

// allowedTypes maps detected content types to permitted file extensions
var allowedTypes = map[string]string{
	"image/jpeg":  ".jpg",
	"image/png":   ".png",
	"image/gif":   ".gif",
	"image/webp":  ".webp",
}

func UploadAvatar(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("avatar")
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

	// Detect the actual content type by inspecting the file's leading bytes
	detectedType := http.DetectContentType(bytes)
	
	// Validate against allowlist
	ext, allowed := allowedTypes[detectedType]
	if !allowed {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Generate a random filename to prevent path traversal and malicious extensions
	randomBytes := make([]byte, 16)
	_, err = rand.Read(randomBytes)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	generatedFilename := hex.EncodeToString(randomBytes) + ext

	// Store the file with the generated name
	storagePath := filepath.Join(storageDir, generatedFilename)
	err = os.WriteFile(storagePath, bytes, 0o600)
	if err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}

	// Return the generated filename to the caller so they can retrieve it
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"filename":"` + generatedFilename + `"}`))
}
```

## Explanation

The fix closes CWE-434 by preventing both file type injection and path traversal attacks. Instead of trusting `header.Filename`, the code now: (1) inspects the actual file content with `http.DetectContentType()` to determine the real MIME type, (2) validates that type against a server-controlled allowlist of permitted image types, (3) generates a cryptographically random filename with an extension derived from the allowlist (not the client-supplied name), and (4) stores the file under that generated name. This eliminates the attacker's ability to control the filename, extension, or storage path. The generated filename is returned in the response body so the caller (or a client) can retrieve the file using the safe name. The fix uses `crypto/rand` for cryptographic randomness and `encoding/hex` to encode it safely as a filename.

## Behaviour changes

**Changed**: The response now returns JSON containing the generated filename instead of a simple `StatusCreated`. Clients that uploaded files must now extract the generated filename from the response and use it in subsequent read requests.

**Unaffected**: File permission mode (`0o600`), error handling paths, and request parsing remain the same.

**Requirement for read path**: The existing `ReadAvatarBytes()` function must be updated to accept the generated filename from callers, not the original filename. This is a contract change - callers must now preserve and send back the generated filename rather than using the original upload filename.
