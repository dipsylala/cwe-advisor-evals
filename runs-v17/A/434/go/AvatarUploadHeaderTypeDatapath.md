## Verdict

The vulnerability is confirmed. The handler at line 21 of avatar_handler.go validates the file type using only the client-supplied `Content-Type` header, which an attacker can spoof. An attacker can upload a malicious executable (e.g., `.php`, `.exe`) by claiming it is an image in the HTTP header, bypassing the validation. Additionally, the filename is taken directly from the client-supplied `header.Filename`, allowing further manipulation.

## Source

**avatar_handler.go, line 21:**
```go
contentType := header.Header.Get("Content-Type")
```

The vulnerability spans two files:
1. **avatar_handler.go**: Trusts the client-supplied Content-Type header for validation
2. **avatar_store.go**: Uses the client-supplied filename directly in filepath.Join without sanitization

The attack chain:
1. Attacker crafts a multipart upload with a `.php` file
2. Attacker sets the Content-Type header to `image/png`
3. Handler validates only the header (line 22-25), not the actual file content
4. File is saved with the attacker-controlled filename (line 27)

## Fix

### File: avatar_handler.go

```go
package avatarupload

import (
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

		// Read first 512 bytes to detect actual content type
		buf := make([]byte, 512)
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}

		// Detect the actual MIME type from file content, not header
		detectedType := http.DetectContentType(buf[:n])

		// Only allow specific image types based on actual content
		if detectedType != "image/png" && detectedType != "image/jpeg" {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Rewind to start of file before saving
		if _, err := file.Seek(0, 0); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		storedName, err := store.Save(detectedType, file)
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

func (s *AvatarStore) Save(mimeType string, file io.Reader) (string, error) {
	// Map MIME type to safe file extension
	var ext string
	switch mimeType {
	case "image/png":
		ext = ".png"
	case "image/jpeg":
		ext = ".jpg"
	default:
		return "", fmt.Errorf("unsupported mime type: %s", mimeType)
	}

	// Generate server-controlled filename with random component
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	filename := hex.EncodeToString(randBytes) + ext

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

The fix implements three key defenses against CWE-434:

**1. Content sniffing instead of header trust (line 21-31 in avatar_handler.go):**
- Read the first 512 bytes of the uploaded file
- Use `http.DetectContentType()` to detect the actual MIME type from magic bytes, not the client-supplied header
- This prevents spoofing: a `.php` file claiming to be `image/png` will be detected as `application/octet-stream` or similar and rejected

**2. Rewind before save (line 41-44 in avatar_handler.go):**
- After reading bytes for detection, seek back to the start of the file
- This allows the store to save the complete file content without losing the header bytes

**3. Server-generated filename (avatar_store.go):**
- Generate a cryptographically random filename using `crypto/rand.Read()`
- Append only the safe extension determined by the actual MIME type
- This prevents:
  - Directory traversal via malicious path components (e.g., `../../../etc/passwd`)
  - Execution of uploaded files if saved to a web-accessible directory (the attacker doesn't control the filename)
  - Conflicts between user uploads

**Preserved behavior:**
- Valid PNG and JPEG uploads return 201 status with the server-generated filename
- Invalid uploads return 400 or 500 with existing error messages
- Caller can retrieve the file using the stored name returned in the response

E:/Github/cwe-advisor/evals/runs-v17/A/434/go/AvatarUploadHeaderTypeDatapath.md
