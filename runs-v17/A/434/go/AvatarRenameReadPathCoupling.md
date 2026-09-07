## Verdict

Confirmed. Line 27 of avatar_upload.go writes to disk using a user-supplied filename without validation, allowing arbitrary file types to be uploaded. The coupled read operation in avatar_lookup.go can then access these files, creating a serious file-type injection risk.

## Source

The vulnerability is in avatar_upload.go line 27:
```go
os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)
```

The `header.Filename` value comes directly from the uploaded multipart form data and is used as-is to write the file to disk. This allows an attacker to upload any file type (e.g., `.sh`, `.exe`, `.php`) that will persist and be accessible via the ReadAvatarBytes function.

## Fix

### File: avatar_upload.go

```go
package avatars

import (
	"crypto/rand"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const storageDir = "/var/app-data/avatars"

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

	// Validate file content is actually an image by decoding header
	_, imageType, err := image.DecodeConfig(bytes)
	if err != nil || !isAllowedImageType(imageType) {
		http.Error(w, "invalid image type", http.StatusBadRequest)
		return
	}

	// Generate safe filename with UUID instead of trusting user-supplied filename
	safeFilename := generateSafeFilename(imageType)

	err = os.WriteFile(filepath.Join(storageDir, safeFilename), bytes, 0o600)
	if err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"filename":"%s"}`, safeFilename)
}

func isAllowedImageType(imageType string) bool {
	allowed := map[string]bool{
		"jpeg": true,
		"png":  true,
		"gif":  true,
		"webp": true,
	}
	return allowed[imageType]
}

func generateSafeFilename(imageType string) string {
	// Generate random UUID-like identifier
	uuid := make([]byte, 16)
	_, _ = rand.Read(uuid)
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant RFC 4122

	ext := strings.ToLower(imageType)
	if ext == "jpeg" {
		ext = "jpg"
	}

	return fmt.Sprintf("%x.%s", uuid, ext)
}
```

## Explanation

The fix addresses CWE-434 by replacing the user-supplied filename with a cryptographically random UUID-based filename. The remediation has three key components:

1. **File type validation via content inspection**: `image.DecodeConfig()` validates that the uploaded bytes are actually a valid image by parsing the magic bytes and format. This rejects non-image files regardless of their supplied extension.

2. **Whitelist of allowed formats**: The `isAllowedImageType()` check restricts uploads to known-safe image formats (JPEG, PNG, GIF, WebP), rejecting any other type that passes format validation.

3. **Safe filename generation**: Instead of using `header.Filename`, a random UUID-based filename is generated with an extension determined by the validated image type. This decouples the filename from user input and prevents an attacker from uploading files as `.sh`, `.php`, `.exe`, or any other dangerous extension.

The coupled read operation in avatar_lookup.go remains safe because it now reads only filenames that were generated during the validated upload process.

