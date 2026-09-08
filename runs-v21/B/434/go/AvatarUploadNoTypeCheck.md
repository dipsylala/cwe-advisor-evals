## Verdict

Exploitable. An attacker can upload any file type (including executable scripts like `.php`, `.html` with script content, or other dangerous types) to the webroot-accessible directory. The server directly serves files from `./public/avatars/` using `http.FileServer`, so a successful upload of a script file results in remote code execution or XSS depending on the server's configuration and the file type.

## Source

**Source:** Client-supplied file upload via `r.FormFile("avatar")` in the multipart form.

**Sink:** Line 32, `os.Create(destPath)` where `destPath` is constructed from `filepath.Join(avatarDir, header.Filename)`. The `header.Filename` value comes directly from the client's multipart form metadata without any validation of type or format.

**Data flow:**
1. Attacker sends multipart POST with arbitrary filename and content (e.g., `shell.php` containing PHP code)
2. `header.Filename` is extracted directly from the client-supplied multipart metadata (untrusted)
3. `filepath.Join(avatarDir, header.Filename)` creates path `./public/avatars/shell.php`
4. `os.Create()` writes the file to that location
5. `http.FileServer` at `/avatars/` route serves the file directly from disk
6. Server (or browser for HTML) executes the uploaded script

## Fix

### File: AvatarUploadNoTypeCheck.go

```go
package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	avatarDir     = "./private/avatars"  // Moved outside webroot
	maxUploadSize = 5 << 20               // 5 MB
)

// allowedMimeTypes maps detected MIME types to allowed stored extensions
var allowedMimeTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	// Register handler to serve avatars from private storage with proper controls
	http.HandleFunc("/avatars/", serveAvatar)
}

func generateFilename() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func serveAvatar(w http.ResponseWriter, r *http.Request) {
	// Extract filename from URL path
	avatarName := filepath.Base(r.URL.Path[len("/avatars/"):])

	// Prevent path traversal
	if avatarName == "" || avatarName == "." || avatarName == ".." {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if strings.Contains(avatarName, "/") || strings.Contains(avatarName, "\\") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	filePath := filepath.Join(avatarDir, avatarName)

	// Verify the resolved path is within avatarDir to prevent escaping
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	absAvatarDir, err := filepath.Abs(avatarDir)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Check containment
	if !strings.HasPrefix(absFilePath, absAvatarDir+string(os.PathSeparator)) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Serve file with proper headers to prevent execution
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	file, err := os.Open(absFilePath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	http.ServeContent(w, r, avatarName, time.Now(), file)
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	// Limit request size before parsing to prevent resource exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the first 512 bytes to detect actual content type
	sniffBuf := make([]byte, 512)
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}

	// Detect the actual content type from file content (magic bytes), not client-supplied header
	detectedType := http.DetectContentType(sniffBuf[:n])

	// Check against allowlist of safe image types
	allowedExt, ok := allowedMimeTypes[detectedType]
	if !ok {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Rewind file for full read after sniffing
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}

	// Generate a random filename; do not use client-supplied filename
	randomName, err := generateFilename()
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	// Extension comes from allowlist, not client-supplied value
	storedName := randomName + allowedExt

	// Ensure avatar directory exists
	if err := os.MkdirAll(avatarDir, 0o700); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	destPath := filepath.Join(avatarDir, storedName)
	// Use O_EXCL to fail if file already exists (protects against TOCTOU race)
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	_, err = io.Copy(dest, file)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	// Return the generated filename to the client so they can retrieve it
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"filename":"%s"}`, storedName)
}
```

## Explanation

The fix addresses CWE-434 through four layers of control:

1. **Content-based type validation:** Replaced trust in client-supplied `header.Filename` extension and `Content-Type` header with server-side `http.DetectContentType()` inspection of actual file magic bytes. Only image MIME types (`image/jpeg`, `image/png`, `image/gif`, `image/webp`) are allowlisted; any other type is rejected immediately.

2. **Generated storage filename:** The original code used the untrusted `header.Filename` directly as the storage path, allowing an attacker to control the extension. The fix generates a random 32-hex-character filename using `crypto/rand` and appends the extension from the allowlist mapping, ensuring the extension matches the detected type and cannot be influenced by the attacker.

3. **Storage outside webroot:** Files are now stored in `./private/avatars/` instead of the webroot-accessible `./public/avatars/`, preventing the web server from directly serving untrusted content. A new `serveAvatar()` handler retrieves files with path traversal protection and sets `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing attacks.

4. **Request size limits and safe file operations:** Added `http.MaxBytesReader()` before parsing to prevent resource exhaustion, explicit `maxMemory` in `ParseMultipartForm()`, and used `os.OpenFile()` with `O_EXCL` flag to prevent TOCTOU races.

The generated filename is returned as JSON in the response so clients can retrieve the uploaded file via the `/avatars/` handler.

## Behaviour changes

1. **Storage location changed:** Files now stored in `./private/avatars/` (outside webroot) instead of `./public/avatars/`. Reason: prevents direct web server execution of uploaded content.

2. **File serving mechanism changed:** Files are no longer served by `http.FileServer` but through the `serveAvatar()` handler that includes path traversal protection. Reason: enables security checks (path containment) and response header controls.

3. **Filenames are generated server-side:** Stored as randomly-generated hex names with allowlist-determined extensions (e.g., `a1b2c3d4e5f6.jpg`), not using `header.Filename`. Reason: prevents attacker control over extension and file type confusion.

4. **Upload response format changed:** Handler now returns JSON `{"filename":"<generated_name>"}` instead of just status code. Reason: client needs the generated name to retrieve the file; without this, the file would be unretrievable.

5. **File permissions enforced:** Files created with `0o600` (read/write for owner only) and directory created with `0o700`. Reason: defense-in-depth access control.

6. **Request size limit enforced:** Uploads capped at 5 MB via `http.MaxBytesReader()`. Reason: prevents resource exhaustion and DoS attacks.

7. **File type restricted to images:** Only `image/jpeg`, `image/png`, `image/gif`, and `image/webp` accepted; all other types rejected immediately. Reason: reduces attack surface to a known-safe set of file types.

All changes are required to close the vulnerability or support the new architecture; none are speculative.
