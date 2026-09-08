## Verdict
CONFIRMED - CWE-434 unrestricted upload vulnerability. The code validates only the client-provided Content-Type header without checking actual file content, allowing an attacker to upload executable files disguised as images.

## Source
The vulnerability is in `avatar_handler.go` line 21, where the code trusts the `Content-Type` header value provided by the client without validating the actual file content. Combined with `avatar_store.go` using the unvalidated `header.Filename`, this allows arbitrary file uploads with dangerous types.

## Fix

### File: avatar_handler.go
```go
package avatarupload

import (
	"bytes"
	"io"
	"net/http"
)

func UploadAvatarHandler(store *AvatarStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("avatar")
		if err != nil {
			http.Error(w, "missing avatar", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Read file into buffer to check magic bytes and validate content
		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, file); err != nil {
			http.Error(w, "failed to read upload", http.StatusInternalServerError)
			return
		}

		fileBytes := buf.Bytes()

		// Validate actual file content by checking magic bytes, not Content-Type header
		isValidImage := isValidImageFile(fileBytes)
		if !isValidImage {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		storedName, err := store.Save(fileBytes)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}

// isValidImageFile checks the actual file magic bytes to detect PNG and JPEG
func isValidImageFile(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// PNG magic bytes: 0x89 0x50 0x4E 0x47
	if len(data) >= 4 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return true
	}

	// JPEG magic bytes: 0xFF 0xD8 0xFF
	if len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return true
	}

	return false
}
```

### File: avatar_store.go
```go
package avatarupload

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type AvatarStore struct {
	Dir string
}

func (s *AvatarStore) Save(fileContent []byte) (string, error) {
	// Generate a random filename to prevent file type injection and path traversal
	randomName := generateSafeFilename()

	// Determine file extension based on actual content
	ext := getImageExtension(fileContent)
	if ext == "" {
		return "", fmt.Errorf("unsupported image format")
	}

	filename := randomName + ext
	target := filepath.Join(s.Dir, filename)

	out, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, io.NopCloser(io.Reader(io.NewReader(fileContent)))); err != nil {
		return "", err
	}

	return filename, nil
}

// generateSafeFilename creates a random hex filename to prevent injection attacks
func generateSafeFilename() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback if randomness fails (shouldn't happen in practice)
		return "avatar_" + fmt.Sprintf("%d", os.Getpid())
	}
	return hex.EncodeToString(b)
}

// getImageExtension determines the correct extension based on file magic bytes
func getImageExtension(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// PNG magic bytes: 0x89 0x50 0x4E 0x47
	if len(data) >= 4 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return ".png"
	}

	// JPEG magic bytes: 0xFF 0xD8 0xFF
	if len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return ".jpg"
	}

	return ""
}
```

## Explanation
The vulnerability is a classic CWE-434 file upload bypass where the client-provided Content-Type header is trusted instead of validating actual file content. An attacker could send an executable file (e.g., `.exe`, `.php`, `.sh`) with `Content-Type: image/png` and it would be saved as an image.

**Primary fixes:**
1. **Validate file magic bytes, not headers** - Check the actual file bytes (PNG: `0x89 0x50 0x4E 0x47`, JPEG: `0xFF 0xD8 0xFF`) instead of trusting the client-provided Content-Type header.
2. **Regenerate filename** - Store files with random hex names (e.g., `a1b2c3d4e5f6g7h8.png`) instead of the user-provided filename. This prevents both path traversal attacks and extension spoofing.
3. **Determine extension from content** - Assign the correct file extension based on detected file type, not user input.

**Secondary defenses:**
- The random filename prevents path traversal exploits (`../../../etc/passwd`)
- Content validation happens before any storage attempt
- The actual file content is buffered and passed directly to storage, preventing double-reads

This ensures that only genuine image files are accepted and stored, regardless of what headers or filenames the attacker provides.
