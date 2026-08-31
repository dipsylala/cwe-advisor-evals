## Verdict

Confirmed. The handler accepts uploaded files without validating their content type or storage path. An attacker can upload a file with a dangerous type (HTML, JavaScript, executable script) disguised with an image extension, or exploit path traversal in the filename. Because the upload is stored in `./public/avatars` and served via `http.FileServer`, a malicious script file will be executed or served to other users.

## Source

The source is the client-supplied multipart form: `header.Filename` at line 30 and the file's `Content-Type` header (not inspected). The source is passed directly to `filepath.Join(avatarDir, header.Filename)` with no validation.

## Fix

```go
package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./private/avatars"

// Allowlist of permitted MIME types and their extensions
var allowedTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	// Serve avatars through a handler, not FileServer, to prevent execution
	http.HandleFunc("/avatars/", serveAvatar)
}

func serveAvatar(w http.ResponseWriter, r *http.Request) {
	// Safe handler: extract base name and serve from private storage
	name := filepath.Base(r.URL.Path)
	http.ServeFile(w, r, filepath.Join(avatarDir, name))
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	// Guard against oversized requests before parsing
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB

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

	// Read up to 512 bytes to detect actual content type
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusInternalServerError)
		return
	}

	// Detect the actual content type from file bytes, not the client-supplied header
	detectedType := http.DetectContentType(buffer[:n])

	// Validate against allowlist of safe types
	ext, ok := allowedTypes[detectedType]
	if !ok {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Rewind file for storage
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "could not seek file", http.StatusInternalServerError)
		return
	}

	// Generate random filename; extension comes from allowlist, not client-supplied name
	randomName := make([]byte, 16)
	if _, err := rand.Read(randomName); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	storedFilename := fmt.Sprintf("%x%s", randomName, ext)
	destPath := filepath.Join(avatarDir, storedFilename)

	// Store with restricted permissions; fail if collision (O_EXCL)
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not write file", http.StatusInternalServerError)
		return
	}

	// Return the generated filename so the caller can retrieve it later
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "avatar saved as %s", storedFilename)
}
```

## Explanation

The fix eliminates four attack vectors simultaneously:

1. **Content-Type validation**: Replaces trust in the client-supplied `Content-Type` header with `http.DetectContentType()`, which reads the file's actual leading bytes (magic number). An attacker cannot upload a `.php` file disguised as `image/jpeg` because the detected type will not match.

2. **Allowlist enforcement**: Restricts uploads to a fixed, server-controlled map (`allowedTypes`) keyed by the detected MIME type. Only image types present in the map are stored; the extension is taken from that map, not from the client-supplied filename. This prevents extension swapping (e.g., uploading `shell.jpg.php` with an image signature).

3. **Filename generation**: Replaces the client-supplied `header.Filename` with a cryptographically random name generated server-side. This prevents path traversal (`../../../etc/passwd`) and eliminates the attacker's ability to predict or control the stored filename.

4. **Storage location**: Moves files to `./private/avatars` outside the public webroot and introduces a custom handler (`serveAvatar`) instead of `http.FileServer`. This ensures uploaded files cannot be executed even if a filtering bypass occurs—the handler serves them with appropriate headers and never interprets them as code.

The fix preserves the handler's contract by returning the generated filename in the response, allowing the caller to store and later retrieve the uploaded file using the server-generated name rather than the untrusted client-supplied one.

## Behaviour changes

**Before**: POST /upload with a multipart file → file stored as-is in public directory with client-supplied name → response: HTTP 201 (no filename returned)

**After**: POST /upload with a multipart file → file content inspected, MIME type detected, validated against allowlist, stored in private directory with random name and allowlist-derived extension → response: HTTP 201 with generated filename in body

Files previously stored with user-supplied names (e.g., "avatar.png") are now stored with random names (e.g., "a1b2c3d4e5f6g7h8.png"). Any retrieval logic that relied on the original filename will break unless updated to use the returned generated name. The calling code must persist the mapping from user ID to generated avatar filename or reconstruct retrieval URLs using the returned name.
