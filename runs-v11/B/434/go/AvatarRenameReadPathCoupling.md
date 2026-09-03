## Verdict

VULNERABLE. The code uses the client-supplied filename (`header.Filename`) directly as the storage path without validation, allowing path traversal. It also does not validate the file's actual content type, permitting uploads of any file type to the storage directory.

## Source

`header.Filename` is obtained from `r.FormFile("avatar")` at line 13, which returns a `multipart.FileHeader` whose `Filename` field is supplied by the client in the multipart form headers. The file content is read into memory at line 20 without content-type validation. Both the filename and unvalidated content are then passed to the sink.

## Fix

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
	"strings"
)

const storageDir = "/var/app-data/avatars"

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

	// Detect actual content type from file bytes
	detectedType := http.DetectContentType(bytes)
	
	// Check against allowlist
	ext, allowed := allowedTypes[detectedType]
	if !allowed {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
		return
	}

	// Generate random filename
	randomBytes := make([]byte, 16)
	_, err = rand.Read(randomBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	generatedName := hex.EncodeToString(randomBytes) + ext

	// Validate path stays within storage directory
	storagePath := filepath.Join(storageDir, generatedName)
	absPath, err := filepath.Abs(storagePath)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	absDirPath, err := filepath.Abs(storageDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !strings.HasPrefix(absPath, absDirPath+string(filepath.Separator)) && absPath != absDirPath {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Write file with O_EXCL to prevent overwrites
	err = os.WriteFile(storagePath, bytes, 0o600)
	if err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	// Return generated filename so caller can retrieve it
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"filename":"%s"}`, generatedName)
	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

The fix addresses both path traversal and unrestricted file type upload:

1. **Content Type Validation**: Calls `http.DetectContentType()` on the actual file bytes (not the client-supplied Content-Type header) and validates against an allowlist. Unsupported types are rejected with HTTP 400.

2. **Filename Generation**: Uses `crypto/rand` to generate a random 16-byte filename, then appends the extension from the allowlist-matched MIME type. This eliminates the path traversal vector where the client could supply traversal sequences like `../../../etc/passwd`.

3. **Path Validation**: Verifies the final path stays within the intended storage directory by comparing absolute paths, catching any cases where path traversal attempts slip through.

4. **Return Generated Name**: The response now includes the generated filename in JSON, so callers and the `ReadAvatarBytes()` function can locate the uploaded file. Without this, the read path would silently break because it would be searching for the original client-supplied filename that no longer exists in storage.

5. **Error Handling**: The fix properly handles errors from random number generation and file operations, returning appropriate HTTP status codes.

## Behaviour changes

- **File Type Enforcement**: The handler now rejects uploads whose detected content type is not in the allowlist (currently JPEG, PNG, GIF, WebP). Previously any file was accepted.
- **Filenames No Longer User-Controlled**: Uploaded files are stored under randomized hex names with detected-type extensions, not the original client-supplied filename. Filenames are now unpredictable.
- **Path Traversal Prevention**: Filenames containing directory separators or traversal sequences can no longer reach storage outside `storageDir`.
- **Response Format Change**: The handler now returns HTTP 201 with a JSON body containing the generated filename: `{"filename":"<hex>.jpg"}`. Callers expecting a different response format must be updated.
- **Updated Read Path Required**: The `ReadAvatarBytes()` function must receive the generated filename from callers instead of the original filename. Any route that serves avatars back to users must now accept the generated name (e.g., as a URL path parameter).
