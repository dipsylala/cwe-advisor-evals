## Verdict

Exploitable. The handler accepts any file type, uses the client-supplied filename directly in a path without validation or sanitization, and stores uploaded files in a directory served by `http.FileServer`, where executable scripts would be directly accessible and potentially executed by the server or browser.

## Source

`r.FormFile("avatar")` at line 23 returns a `multipart.FileHeader` with user-controlled `Filename` and `Content-Type` fields. The source is attacker-supplied multipart form data in the HTTP request.

## Fix

**Vulnerable code** (lines 17–41):

```go
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

	destPath := filepath.Join(avatarDir, header.Filename)
	// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	io.Copy(dest, file)
	w.WriteHeader(http.StatusCreated)
}
```

**Fixed code**:

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./public/avatars"

// allowedMimeTypes maps detected MIME types to their safe file extensions
var allowedMimeTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	// Uploaded avatars are served back directly from this directory.
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	maxUploadSize := int64(5 << 20) // 5 MB limit

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
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
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}

	// Detect actual content type from file content, not client-supplied header
	detectedMimeType := http.DetectContentType(buf[:n])

	// Validate against allowlist
	extension, allowed := allowedMimeTypes[detectedMimeType]
	if !allowed {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Generate random filename using cryptographic randomness
	randomBytes := make([]byte, 16)
	_, err = rand.Read(randomBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	generatedFilename := hex.EncodeToString(randomBytes) + extension

	// Build destination path from generated filename only
	destPath := filepath.Join(avatarDir, generatedFilename)

	// Create file with O_EXCL to fail if it already exists, and restrict permissions
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// Rewind to file start and copy entire content
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not process file", http.StatusBadRequest)
		return
	}

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not write file", http.StatusInternalServerError)
		return
	}

	// Return generated filename to client so it can retrieve the avatar
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"filename": generatedFilename})
}
```

## Explanation

The original code accepted any file with any extension and stored it using the client-supplied filename in a directory served by `http.FileServer`. An attacker could upload `shell.php` or `script.aspx` and access it directly to execute arbitrary code.

The fix addresses the vulnerability by:

1. **Content validation** — Read the file's leading 512 bytes and call `http.DetectContentType()` to determine the real MIME type instead of trusting the client-supplied `Content-Type` header or filename extension.

2. **Allowlist enforcement** — Compare the detected MIME type against a map of permitted types (image formats in this case) and reject anything else immediately.

3. **Filename regeneration** — Generate a random filename using `crypto/rand` instead of using `FileHeader.Filename`, which may contain path separators or traversal sequences. The extension is derived from the allowlist map entry, not from the original filename, so the attacker cannot influence what type the server treats the file as.

4. **Secure file creation** — Use `os.OpenFile()` with `O_EXCL` to fail atomically if the file already exists, and set file permissions to `0o600` to restrict access.

5. **Client response** — Return the generated filename to the client so subsequent requests can locate the uploaded file, preserving the handler's contract without relying on the original client-supplied name.

## Behaviour changes

1. **Filename ownership** — The application now generates the stored filename; the client-supplied name is discarded. The response body now includes the generated filename so the client can retrieve it in subsequent requests (breaking change if the original caller was silently relying on the original filename, but necessary for the security fix).

2. **File size limit** — An explicit `maxUploadSize` of 5 MB is enforced via `ParseMultipartForm` argument. The original code accepted 10 MB with no way to reject oversized requests before they consumed resources.

3. **Accepted types** — Only image MIME types (image/jpeg, image/png, image/gif, image/webp) are accepted; all other uploads are rejected with HTTP 400. The original code accepted any type.

4. **File permissions** — Uploaded files are created with `0o600` permissions, restricting read/write to the application's user alone. The original code used the default process umask.

5. **File creation atomicity** — `O_EXCL` flag ensures the file is created atomically and fails if a collision occurs (negligible risk with random names, but a defensive check).

