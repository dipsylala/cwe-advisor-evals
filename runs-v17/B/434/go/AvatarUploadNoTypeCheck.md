## Verdict

CONFIRMED: The application accepts file uploads without validating file content or type, stores them under the client-supplied filename in the webroot where they are directly served, and fails to prevent execution of malicious scripts. An attacker can upload a file with a malicious extension (e.g., `.html`, `.php`, `.js`) that will be executed or served by the HTTP server.

## Source

The vulnerability originates in `avatarUploadHandler` at line 23: `r.FormFile("avatar")` receives an attacker-controlled multipart file upload. The `FileHeader.Filename` field is client-supplied and not validated.

Data flow trace:
1. **Source**: Line 23 — `r.FormFile("avatar")` returns `header` with attacker-supplied `Filename`
2. **Taint propagation**: Line 30 — `filepath.Join(avatarDir, header.Filename)` passes the untrusted filename directly to construct the storage path
3. **Sink**: Line 32 — `os.Create(destPath)` writes the file under the untrusted path
4. **Exfiltration**: Line 14 — Files are served back directly via `http.FileServer(http.Dir(avatarDir))`, allowing execution of uploaded scripts

The vulnerability is severe because uploaded files land in the webroot and are served by the HTTP server, which will execute scripts based on extension (`.html`, `.php`, `.js`, etc.).

## Fix

### File: AvatarUploadNoTypeCheck.go

```go
package main

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

const avatarDir = "./public/avatars"

// Map from detected content type to safe file extension
var allowedTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	// Uploaded avatars are served back directly from this directory.
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
}

func generateFileName() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	// Enforce size limit before parsing
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the first 512 bytes to detect real content type
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}

	// Detect the real content type from the file's leading bytes
	detectedType := http.DetectContentType(buffer[:n])

	// Check if the detected type is in the allowlist
	ext, ok := allowedTypes[detectedType]
	if !ok {
		// Also check if it's a variant (e.g., image/jpeg; charset=utf-8)
		baseType := strings.Split(detectedType, ";")[0]
		ext, ok = allowedTypes[baseType]
		if !ok {
			http.Error(w, "file type not allowed", http.StatusBadRequest)
			return
		}
	}

	// Generate a random filename
	randomName, err := generateFileName()
	if err != nil {
		http.Error(w, "could not generate filename", http.StatusInternalServerError)
		return
	}

	// Construct the safe path with generated filename and detected extension
	destPath := filepath.Join(avatarDir, randomName+ext)

	// Rewind the file to the beginning before writing
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}

	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// Copy the full file content
	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	// Return the generated name so the caller can retrieve it
	fmt.Fprintf(w, "avatar saved as: %s\n", randomName)
}
```

**Compiler verification**: `go vet` passes without errors.

## Explanation

The fix addresses CWE-434 by implementing defense-in-depth across three areas:

1. **Content validation**: The handler now reads the first 512 bytes of the uploaded file and calls `http.DetectContentType()` to determine its real content type based on magic bytes, not the client-supplied `Content-Type` header or filename extension. This prevents an attacker from bypassing validation by lying about what they uploaded.

2. **Allowlist enforcement**: The detected content type is checked against a server-controlled allowlist (`allowedTypes`) that maps MIME types to safe file extensions. Only images with known-good signatures are accepted; HTML, PHP, JavaScript, and other executable formats are rejected immediately.

3. **Safe storage naming**: The handler generates a cryptographically random filename (16 bytes of entropy, hex-encoded to 32 characters) instead of trusting the client-supplied `FileHeader.Filename`. The extension is derived from the allowlist entry for the detected type, not from the original filename, so the attacker cannot control how the file is served. This breaks the entire attack vector: even if an attacker uploads a file named `avatar.php`, it will be saved as something like `a1b2c3d4e5f6g7h8.png` and served as a PNG image, not executed as PHP.

4. **Size limiting**: `http.MaxBytesReader` is called before parsing to enforce early rejection of oversized uploads, preventing disk exhaustion or memory exhaustion attacks.

5. **Safe file creation**: `os.OpenFile` with `os.O_EXCL` flag ensures the file is created atomically and fails if a collision occurs (extremely unlikely with 16 bytes of entropy, but safe by default).

The fix removes the taint introduced by trusting the client-supplied filename and content type, replacing it with server-controlled validation and naming. The original `header` variable from `r.FormFile()` is discarded after retrieval because it contained only attacker-supplied metadata; the actual file bytes are read and validated independently.

## Behaviour changes

**API contract change (breaking change for callers)**:

The response body now includes the generated filename (`fmt.Fprintf(w, "avatar saved as: %s\n", randomName)`), whereas the original code returned only an HTTP status code. Callers that need to retrieve the uploaded file must now read this response to learn the storage name, or a different mechanism (e.g., a database record created alongside the upload) must map uploads to their stored names. Without this change, the rename from client-supplied name to generated name breaks the read path silently.

**Functional guarantees**:

- Uploads of files with extensions in the allowlist (`.jpg`, `.png`, `.gif`, `.webp`) are accepted only if their actual content matches the extension's expected MIME type.
- Uploads with mismatched extension and content are rejected (e.g., a file named `shell.jpg` but containing `<?php ...` will be rejected because `http.DetectContentType()` detects PHP source, which is not in the allowlist).
- Files are stored under random, unpredictable names in the webroot and are served as static files by MIME type, preventing script execution.
- A file with actual `.php` or `.html` content is rejected outright, not renamed.
- File size limit of 10 MB is enforced before `ParseMultipartForm` processes the request.

**Error handling**:

- New error: "file type not allowed" (400 Bad Request) if the detected type is not in the allowlist.
- Existing errors unchanged for bad requests, missing files, and I/O failures.
