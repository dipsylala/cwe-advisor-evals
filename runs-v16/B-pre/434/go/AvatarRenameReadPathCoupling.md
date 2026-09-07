## Verdict

exploitable

## Source

Client-supplied multipart form file upload (`r.FormFile("avatar")` in line 13) with untrusted filename and unvalidated content.

## Sink

Line 27: `os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)`

The filename written to disk comes directly from `header.Filename`, which is client-supplied multipart part metadata and may contain path traversal sequences (e.g., `../../../etc/passwd.jpg`). Additionally, no validation of the file's actual content type occurs; an attacker can upload a PHP script with a `.jpg` extension, or rename it to avoid extension-based filtering that might be applied elsewhere.

## Fix

**Vulnerable Code:**

```go
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

	// VULNERABLE: Using client-supplied header.Filename directly
	os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)
	w.WriteHeader(http.StatusCreated)
}
```

**Fixed Code:**

```go
package avatars

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const storageDir = "/var/app-data/avatars"

// Allowlist of permitted content types mapped to safe storage extensions
var allowedTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
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

	// Detect actual content type from file leading bytes (not from client-supplied header or extension)
	detectedType := http.DetectContentType(bytes)

	// Validate against allowlist of permitted types
	ext, ok := allowedTypes[detectedType]
	if !ok {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Generate a random filename to break taint and prevent traversal attacks
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	generatedFilename := hex.EncodeToString(randBytes) + ext

	// Store file under generated name (not client-supplied filename)
	storagePath := filepath.Join(storageDir, generatedFilename)
	if err := os.WriteFile(storagePath, bytes, 0o600); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}

	// Return the generated filename to the caller so it can be used for later retrieval
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(generatedFilename))
}
```

## Explanation

The fix closes the CWE-434 weakness by implementing the three core defences: (1) content-type validation using `http.DetectContentType()` to inspect actual file bytes rather than trusting the client-supplied `Content-Type` header or filename extension; (2) an allowlist of permitted MIME types with a fixed mapping to safe storage extensions, so the stored file's extension comes from the detected type, not the client input; (3) a generated random filename using `crypto/rand` to break the taint chain, prevent path traversal sequences in filenames, and ensure the stored file cannot be influenced by attacker-controlled metadata. The response body now contains the generated filename, which must be persisted or returned to the caller (as JSON, plain text, or a database record) so that the read path (`ReadAvatarBytes` or any handler that retrieves the file) can locate it by the generated name instead of the original. This ensures the caller's contract is preserved: the helper function's signature does not change, but the caller must now pass the generated filename rather than the original one.

## Behaviour changes

- Response body now contains the generated filename (plain text): previously, no body was sent. **Reason:** The generated filename is mandatory for retrieval; without persisting or returning it, the upload succeeds but the file becomes unretrievable.
- Response `Content-Type` header set to `text/plain`: previously, no `Content-Type` was set. **Reason:** Explicit content-type header when sending a response body is a best practice.
- Function now returns an error response if `http.DetectContentType()` rejects the file type: previously, any file was accepted. **Reason:** This is the core vulnerability remediation.
- Implicit permission mode for the stored file (`0o600`) is preserved. **Reason:** No change to this contract.
- Error handling for `rand.Read()` failure is added: previously, file randomness was not in scope. **Reason:** Defensive programming; random generation must not be silent if it fails.

