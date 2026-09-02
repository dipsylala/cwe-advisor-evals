## Verdict

Exploitable. The handler trusts the client-supplied `Content-Type` header (line 21) to validate file type without inspecting actual content, and passes the untrusted filename from the request directly to storage (line 27). An attacker can upload a PHP file or other executable by setting a fake `Content-Type: image/png` header, bypassing validation and having it stored with their chosen filename and extension where it can be executed.

## Source

`r.FormFile("avatar")` supplies the attacker-controlled `header.Header.Get("Content-Type")` and `header.Filename`. The Content-Type validation at line 21-25 of avatar_handler.go trusts the client-supplied header without reading the actual file content. The `header.Filename` flows to `store.Save(header.Filename, file)` at line 27, where avatar_store.go line 14 uses it directly in `filepath.Join(s.Dir, filename)` as the storage path, with the client-chosen extension dictating how the file is later served.

## Fix

**Vulnerable code (avatar_handler.go, lines 21-27):**

```go
		contentType := header.Header.Get("Content-Type")
		if contentType != "image/png" && contentType != "image/jpeg" {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		storedName, err := store.Save(header.Filename, file)
```

**Fixed code (avatar_handler.go):**

```go
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
		header512 := make([]byte, 512)
		n, err := file.Read(header512)
		if err != nil && err != io.EOF {
			http.Error(w, "failed to read file", http.StatusInternalServerError)
			return
		}
		header512 = header512[:n]

		// Detect actual content type from file content, not client header
		detectedType := http.DetectContentType(header512)
		
		// Allowlist permitted MIME types
		allowedTypes := map[string]string{
			"image/png":  ".png",
			"image/jpeg": ".jpeg",
		}
		
		ext, ok := allowedTypes[detectedType]
		if !ok {
			http.Error(w, "unsupported file type", http.StatusBadRequest)
			return
		}

		// Rewind file for reading from the start
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			http.Error(w, "failed to process file", http.StatusInternalServerError)
			return
		}

		storedName, err := store.Save(file, ext)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}
```

**Vulnerable code (avatar_store.go, lines 13-26):**

```go
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

**Fixed code (avatar_store.go):**

```go
import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (s *AvatarStore) Save(file io.Reader, ext string) (string, error) {
	// Generate random filename instead of using client-supplied name
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	filename := hex.EncodeToString(randomBytes) + ext

	// Verify the resulting path stays within the intended directory
	target := filepath.Join(s.Dir, filename)
	target = filepath.Clean(target)
	if !filepath.IsAbs(target) || !isWithinDir(target, s.Dir) {
		return "", fmt.Errorf("invalid storage path")
	}

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

// Helper to verify path stays within storage directory
func isWithinDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && !strings.HasPrefix(rel, "..")
}
```

## Explanation

The fix replaces client-supplied validation with content-based detection. Instead of trusting the `Content-Type` header, the handler now reads the first 512 bytes of the uploaded file and calls `http.DetectContentType()` to determine its actual MIME type. This is checked against an allowlist (image/png, image/jpeg), rejecting any file whose content does not match an allowed type. The file is then rewound to its start. The handler no longer passes the client-supplied filename to storage; instead it passes the file stream and the validated extension. The `Save()` function now generates a random filename using `crypto/rand` and appends the extension derived from the allowlist (not the client's original extension), ensuring the attacker cannot choose what extension is stored. The file is created with mode 0o600 (owner read/write only) and the path is validated to remain within the intended storage directory, closing path-traversal attacks on both storage and later retrieval.

## Behaviour changes

- **File signature inspection**: The handler now consumes the first 512 bytes to detect content type. The file is rewound before passing to storage, so no data is lost, but the handler must call `file.Seek(0, io.SeekStart)` after sniffing. This is a standard practice for multipart file handling and does not break the existing contract as long as the rewind succeeds (which it will for `multipart.File` objects).
- **Filename is generated, not provided**: The caller receives a server-generated random filename in the response, not the original client-supplied name. Any code that expects to retrieve the file by its original upload name will silently break if this change is not coordinated with the retrieval path (e.g., if a database record or session stores the original filename, it must be updated to store and use the returned generated name instead).
- **Extension is derived from detected type, not from client filename**: The stored extension comes from the allowlist map, not from `filepath.Ext(header.Filename)`. This prevents extension spoofing but means the stored extension is now determined by the server, not the client.
- **File permissions are restricted**: Files are now created with mode 0o600 (owner read/write only) instead of the default permissions from `os.Create()`, reducing exposure if the storage directory is misconfigured.
