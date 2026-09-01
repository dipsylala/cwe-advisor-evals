## Verdict

**VULNERABLE** - The handler trusts the client-supplied Content-Type header to validate file type, which can be spoofed. An attacker can upload a malicious executable file with a fake Content-Type header of "image/png", bypassing the type check.

## Source

**File**: `avatar_handler.go`, **Line**: 21

The vulnerable code reads the Content-Type header directly from the multipart form:
```go
contentType := header.Header.Get("Content-Type")
```

This header is client-supplied in the multipart part metadata and not verified by the standard library. An attacker can set this to any value, such as "image/png", regardless of the actual file content. The handler then uses the original filename directly without sanitization (line 27), allowing arbitrary file extensions and names to be stored.

## Fix

Replace lines 20-25 and line 27 with the following approach:

1. Read the file content and use `http.DetectContentType()` to determine the actual MIME type
2. Validate against an allowlist of permitted types
3. Generate a safe, random filename with the correct extension
4. Pass the generated filename to storage

Fixed code:

```go
package avatarupload

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Mapping from detected MIME type to safe file extension
var mimeToExt = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpeg",
}

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

		// Read leading bytes to detect actual content type
		buf := make([]byte, 512)
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}

		// Detect the real content type from file content, not header
		detectedType := http.DetectContentType(buf[:n])

		// Validate against allowlist
		ext, allowed := mimeToExt[detectedType]
		if !allowed {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Reset file position after sniffing
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			http.Error(w, "seek failed", http.StatusInternalServerError)
			return
		}

		// Generate a safe filename with the detected extension
		safeName := generateSafeFilename(ext)

		storedName, err := store.Save(safeName, file)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}

// generateSafeFilename creates a random filename with the given extension
func generateSafeFilename(ext string) string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b) + ext
}

type AvatarStore struct {
	Dir string
}

func (s *AvatarStore) Save(filename string, file io.Reader) (string, error) {
	target := filepath.Join(s.Dir, filename)
	out, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}

	return filename, nil
}
```

## Explanation

The vulnerability stems from relying on the client-supplied Content-Type header (`header.Header.Get("Content-Type")`) to validate file type. This header is part of the multipart form metadata and can be trivially spoofed by an attacker. The unsafe pattern trusts this unsupported claim and the original filename without inspection.

The fix uses two complementary controls:

1. **Content validation**: Call `http.DetectContentType()` on the first 512 bytes of the opened file to determine the actual MIME type based on file content (magic bytes), not client claims. This detects the real file type regardless of filename extension or submitted headers.

2. **Safe filename generation**: Generate a random filename using `crypto/rand` and derive the extension from a fixed allowlist map (`mimeToExt`) keyed by the detected type. This prevents:
   - Arbitrary file extensions that could be executed by the server
   - Path traversal sequences in the original filename
   - Confusion between the upload's claimed and actual type

The file position is reset with `Seek(0, io.SeekStart)` after sniffing so the full content is available for storage. Only files with detected MIME types present in the allowlist are accepted; all others are rejected with HTTP 400.

## Behaviour changes

- Files are no longer stored under their original client-supplied names; instead they are stored as random hex strings (e.g., `3f4a2c1e9b7d5a6f.png`) with extensions derived from their actual detected content type
- Requests containing files with Content-Type headers that do not match the actual file content will now be rejected (e.g., an executable uploaded with Content-Type: image/png)
- The response body still contains the stored filename; callers must use this returned name to retrieve the file
- File upload processing slightly increases in latency due to the 512-byte read for content detection; this is outweighed by the security improvement
- Rejection of valid image uploads is prevented as long as the actual file content is PNG or JPEG, regardless of extension or claimed Content-Type
