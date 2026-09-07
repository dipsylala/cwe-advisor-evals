## Verdict

CWE-434 confirmed. The handler trusts the client-supplied `Content-Type` header (line 21) without verifying actual file content, and passes the client-supplied `Filename` directly to storage without generating a server-side name or validating the path stays within the intended directory.

## Source

Line 21 of avatar_handler.go: `contentType := header.Header.Get("Content-Type")`

The `Content-Type` header and `Filename` come from the multipart form data, which is fully attacker-controlled.

## Fix

**avatar_handler.go:**

```go
package avatarupload

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
)

// Allowlist of permitted content types by detected type
var permittedTypes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpeg",
}

func UploadAvatarHandler(store *AvatarStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Guard against oversized uploads before parsing
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB
		
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
		sniff := make([]byte, 512)
		n, err := file.Read(sniff)
		if err != nil && err != io.EOF {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}

		// Detect the real content type from file content
		detectedType := http.DetectContentType(sniff[:n])

		// Validate against allowlist
		ext, ok := permittedTypes[detectedType]
		if !ok {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Reset file pointer to beginning for storage
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		// Generate a random server-side filename
		randomName := make([]byte, 16)
		if _, err := rand.Read(randomName); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}
		generatedName := hex.EncodeToString(randomName) + ext

		storedName, err := store.Save(generatedName, file)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}
```

**avatar_store.go:**

```go
package avatarupload

import (
	"io"
	"os"
	"path/filepath"
)

type AvatarStore struct {
	Dir string
}

func (s *AvatarStore) Save(filename string, file io.Reader) (string, error) {
	// Ensure filename is just a base name with no path separators
	safeName := filepath.Base(filename)
	
	// Construct the full path and clean it
	target := filepath.Join(s.Dir, safeName)
	cleanedPath := filepath.Clean(target)
	
	// Verify the cleaned path stays within the intended directory
	dirAbs, err := filepath.Abs(s.Dir)
	if err != nil {
		return "", err
	}
	
	targetAbs, err := filepath.Abs(cleanedPath)
	if err != nil {
		return "", err
	}
	
	// Ensure the target path is within the directory
	if !isInDir(targetAbs, dirAbs) {
		return "", os.ErrPermission
	}
	
	out, err := os.OpenFile(cleanedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		_ = os.Remove(cleanedPath) // Clean up on failure
		return "", err
	}

	return safeName, nil
}

// isInDir checks if path is within dir
func isInDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && rel != ".." && !contains(rel, "..")
}

func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

## Explanation

The fix replaces the unsafe header-based type check with actual content detection and generates a server-side filename.

**avatar_handler.go changes:**
- Removed: Trusting `header.Header.Get("Content-Type")` (line 21). This header is client-supplied multipart metadata.
- Added: `http.MaxBytesReader` to reject oversized requests before parsing, preventing memory/disk exhaustion.
- Added: Sniffing the first 512 bytes with `http.DetectContentType()` to detect the actual file content type, not the claimed type.
- Added: Allowlist validation against `permittedTypes`, which maps detected MIME types to safe extensions.
- Changed: File pointer rewound with `Seek(0, io.SeekStart)` after sniffing to restore the position for storage.
- Changed: Generated random 16-byte filename with `crypto/rand` and `hex.EncodeToString`, suffixed with the allowlist-determined extension. The server now controls the stored filename, not the attacker.
- Preserved: Response contract—the stored name is still returned to the caller.

**avatar_store.go changes:**
- Changed: `filepath.Base()` called on the filename to extract only the basename, rejecting path separators and traversal sequences.
- Added: Path validation using `filepath.Abs()` and `isInDir()` to verify the cleaned path stays within the intended directory before writing.
- Changed: `os.Create()` replaced with `os.OpenFile(..., os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`. The `O_EXCL` flag fails if the file already exists (preventing collision races), and `0o600` restricts permissions to owner read/write.
- Added: Cleanup on write failure—if `io.Copy` fails, the partial file is removed to avoid orphaning partial uploads.
- Added: Helper functions `isInDir()` to prevent path traversal attacks by ensuring the final path cannot escape the storage directory.

## Behaviour changes

- **Uploads with wrong content vs. extension are now rejected.** An attacker cannot upload a `.php` executable and claim it's `image/png`—detection happens on actual bytes.
- **Filenames are now randomly generated server-side.** The original filename is no longer used for storage, breaking path traversal attacks like `../../../etc/passwd`.
- **Requests larger than 10 MB are now rejected early.** `http.MaxBytesReader` prevents oversized uploads from exhausting resources.
- **Stored files now have restricted permissions (`0o600`).** Only the owner can read/write, hardening access.
- **File race-condition protection.** `O_EXCL` ensures only one goroutine succeeds if two simultaneously try to write the same generated name.
- **Response contract preserved.** The generated server-side filename is still returned to the caller in the response body, so existing clients can retrieve the uploaded file by requesting it through the normal retrieval path. If the handler previously depended on the original filename to locate files on retrieval, a mapping or persistence layer must track the mapping between original and generated names, or all reads must be updated to use the returned name.
