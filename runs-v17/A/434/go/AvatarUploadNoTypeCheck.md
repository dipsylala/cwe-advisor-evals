## Verdict
CONFIRMED

## Source
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

## Fix

### File: AvatarUploadNoTypeCheck.go

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const avatarDir = "./public/avatars"

func init() {
	// Uploaded avatars are served back directly from this directory.
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
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

	// Validate file extension against whitelist of allowed image types
	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowedExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".webp": true,
	}
	if !allowedExts[ext] {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Read file content to validate MIME type
	fileData := make([]byte, 512)
	n, _ := file.Read(fileData)
	mimeType := http.DetectContentType(fileData[:n])
	
	// Verify MIME type is an image
	if !strings.HasPrefix(mimeType, "image/") {
		http.Error(w, "file must be an image", http.StatusBadRequest)
		return
	}
	
	// Reset file pointer for copying
	file.Seek(0, 0)

	// Generate a safe filename using random ID to prevent path traversal and overwrite attacks
	randomID := make([]byte, 16)
	if _, err := rand.Read(randomID); err != nil {
		http.Error(w, "could not generate filename", http.StatusInternalServerError)
		return
	}
	safeFilename := hex.EncodeToString(randomID) + ext
	destPath := filepath.Join(avatarDir, safeFilename)

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

## Explanation

The vulnerability exists because the code accepts any uploaded file without validating its type, creating a path where an attacker can upload executable files (shell scripts, executables) or other dangerous content that could be served back or executed.

The fix implements three layers of defense:

1. **File extension whitelist**: Validates that the extension is a known image type (jpg, jpeg, png, gif, webp), rejecting suspicious or executable extensions upfront.

2. **MIME type validation**: Uses `http.DetectContentType()` to inspect the actual file content and confirm it matches an image MIME type. This prevents attackers from uploading a shell script with a .jpg extension.

3. **Safe filename generation**: Replaces the user-supplied filename with a cryptographically random hex string plus the validated extension, preventing path traversal attacks (e.g., `../../../etc/passwd.jpg`) and reducing the attack surface further. The original filename is not trusted for any part of the file path.

The file pointer is reset with `Seek(0, 0)` after reading the first 512 bytes for detection, ensuring the complete file content is copied to disk.
