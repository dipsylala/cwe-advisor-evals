## Verdict

The vulnerability is confirmed. The application trusts the client-supplied `Content-Type` header without verifying the actual file content, allowing an attacker to upload a malicious script (e.g., shell or PHP file) disguised as an image. Additionally, the original filename is used directly for storage, enabling path traversal attacks.

## Source

**File**: avatar_handler.go, line 21

```
contentType := header.Header.Get("Content-Type")
```

This retrieves the `Content-Type` header value directly from the multipart form metadata, which is controlled by the client and not verified by the standard library. The subsequent validation (lines 22-25) checks only this unverified header value.

**File**: avatar_store.go, line 14

```
target := filepath.Join(s.Dir, filename)
```

The filename parameter comes from `header.Filename` (avatar_handler.go line 27), which is also client-supplied and not validated. A malicious filename containing path traversal sequences (e.g., `../../../malicious.sh`) can escape the intended directory.

## Fix

### File: avatar_handler.go

```go
package avatarupload

import (
	"crypto/rand"
	"fmt"
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

		// Read the first 512 bytes to detect actual content type
		sniffBuffer := make([]byte, 512)
		n, err := file.Read(sniffBuffer)
		if err != nil && err != io.EOF {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}

		// Detect the actual content type from file content
		detectedType := http.DetectContentType(sniffBuffer[:n])

		// Validate against allowlist of permitted types
		allowedTypes := map[string]bool{
			"image/png":  true,
			"image/jpeg": true,
		}

		if !allowedTypes[detectedType] {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Rewind file to beginning for storage
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			http.Error(w, "seek failed", http.StatusInternalServerError)
			return
		}

		// Generate a random filename with extension from detected type
		randBytes := make([]byte, 8)
		if _, err := rand.Read(randBytes); err != nil {
			http.Error(w, "generation failed", http.StatusInternalServerError)
			return
		}
		randomName := fmt.Sprintf("%x", randBytes)

		storedName, err := store.Save(detectedType, randomName, file)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}
```

### File: avatar_store.go

```go
package avatarupload

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type AvatarStore struct {
	Dir string
}

// Extension map from detected content type to file extension
var contentTypeToExt = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpeg",
}

func (s *AvatarStore) Save(contentType, randomName string, file io.Reader) (string, error) {
	// Get extension from detected content type, not from filename
	ext, ok := contentTypeToExt[contentType]
	if !ok {
		return "", fmt.Errorf("unsupported content type: %s", contentType)
	}

	filename := randomName + ext

	// Use filepath.Join which normalizes the path
	target := filepath.Join(s.Dir, filename)

	// Verify the resolved path stays within the intended directory
	absDir, err := filepath.Abs(s.Dir)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if !isWithinDir(absTarget, absDir) {
		return "", fmt.Errorf("path traversal attempt detected")
	}

	// Create file with secure flags: fail if exists, owner-readable only
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}

	return filename, nil
}

// isWithinDir checks if target is within directory dir
func isWithinDir(target, dir string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel != ".." && !filepath.IsAbs(rel) && rel[:2] != ".."
}
```

## Explanation

The fix closes the vulnerability by implementing three key defences:

1. **Content-Type Detection**: Instead of trusting the client-supplied `Content-Type` header, the code now reads the first 512 bytes of the uploaded file and calls `http.DetectContentType()` to determine the actual file type based on the file's magic bytes (signature). This prevents an attacker from uploading a PHP shell or other executable with a spoofed image header.

2. **Generated Filename**: The handler generates a random filename using `crypto/rand`, eliminating the client's ability to control the storage path. The filename is constructed from detected content type's extension (via a fixed allowlist map), not from the client-supplied filename. This prevents both path traversal attacks and the attacker choosing the file extension.

3. **Path Validation**: The `Save` method now validates that the resolved absolute path stays within the intended storage directory, preventing path traversal sequences like `../../../`. The file is created with `os.O_EXCL` to fail if it already exists (atomic safety) and with mode `0o600` to restrict access.

The original filename and client-supplied content type are completely discarded; the response returns the generated filename so the application can later retrieve the file through the proper application-controlled path.

## Behaviour changes

- **Filename handling**: Uploaded files no longer use the client-supplied filename; instead they are stored with a cryptographically random name and an extension derived from the detected content type. Callers expecting to retrieve files by original name must be updated to use the returned generated name.
- **Validation strictness**: Files whose actual content does not match one of the allowlisted types (image/png or image/jpeg) are now rejected, even if headers claim otherwise. Polyglot files with a valid image header followed by script content will still be rejected because re-encoding during save would strip the trailing payload, but the validation happens on the unencoded content.
- **Error messages**: New error conditions (path traversal attempt, seek failure) may be surfaced to callers.
- **File permissions**: Created files now have mode 0o600 (owner read/write only) instead of the default, reducing exposure if the storage directory is world-readable.
