## Verdict
Confirmed. The code accepts file uploads without validating file type or extension, allowing an attacker to upload executable or dangerous files that may be executed when served via the HTTP file server.

## Source
The vulnerability is at line 32. The function accepts a file upload and saves it using the client-supplied `header.Filename` directly, with no validation of the file type or extension:

```go
destPath := filepath.Join(avatarDir, header.Filename)
dest, err := os.Create(destPath)
```

Because the uploaded files are then served via `http.FileServer` (line 14), an attacker can upload a file with a dangerous extension (e.g., `.exe`, `.sh`, `.jsp`) or MIME type that may be executed by a browser or the server.

## Fix
Validate the file's MIME type and extension. Generate a safe filename using a UUID, then append a sanitized extension based on the allowed MIME type:

```go
import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const avatarDir = "./public/avatars"

// allowedMimeTypes maps MIME types to their safe file extensions
var allowedMimeTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
}

func generateSafeFilename() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read first 512 bytes to detect MIME type
	buffer := make([]byte, 512)
	n, _ := file.Read(buffer)
	detectedMimeType := http.DetectContentType(buffer[:n])

	// Extract base MIME type (remove parameters like charset)
	mimeType := strings.Split(detectedMimeType, ";")[0]

	// Validate MIME type against whitelist
	safeExt, allowed := allowedMimeTypes[mimeType]
	if !allowed {
		http.Error(w, "invalid file type", http.StatusBadRequest)
		return
	}

	// Generate safe filename with validated extension
	safeFilename, err := generateSafeFilename()
	if err != nil {
		http.Error(w, "could not generate filename", http.StatusInternalServerError)
		return
	}
	safeFilename += safeExt

	destPath := filepath.Join(avatarDir, safeFilename)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// Seek back to beginning of uploaded file and copy
	file.Seek(0, 0)
	io.Copy(dest, file)
	w.WriteHeader(http.StatusCreated)
}
```

## Explanation
The fix addresses CWE-434 by implementing two complementary defences:

1. **MIME type whitelist**: Use `http.DetectContentType()` to detect the actual file type based on the file's magic bytes (content), not the client-supplied extension. Only allow safe image types (JPEG, PNG, GIF, WebP).

2. **Safe filename generation**: Generate a random filename using a cryptographic random UUID and append only the validated extension. This prevents directory traversal (`../`), executable extensions, and other dangerous filenames regardless of what the client supplied.

The buffer read for MIME detection is seeked back to the beginning before copying, ensuring the entire file is saved. This dual approach ensures that even if one defence is misconfigured, the other prevents exploitation.
