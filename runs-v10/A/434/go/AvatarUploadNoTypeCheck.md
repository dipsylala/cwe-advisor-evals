## Verdict

**CONFIRMED.** The code accepts any file type without validation. On line 32, `os.Create()` writes the uploaded file directly to disk based on user-supplied `header.Filename`. Since the avatars directory is then served as-is via `http.FileServer()` (line 14), an attacker can upload and execute dangerous file types such as `.php`, `.exe`, or shell scripts, depending on server configuration.

## Source

**Line 30:** `destPath := filepath.Join(avatarDir, header.Filename)` — The destination path is constructed directly from the user-supplied filename with no validation.

**Line 32:** `dest, err := os.Create(destPath)` — The file is written without any preceding check of its type.

**Line 14:** `http.FileServer(http.Dir(avatarDir))` — The uploaded files are served back directly to clients, allowing execution if the server is misconfigured.

## Fix

Add file type validation **before** creating the file. Check the MIME type or file extension to ensure only image uploads are allowed:

```go
import (
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Allowlist of permitted MIME types for avatar images
var allowedMimeTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
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

	// Validate MIME type from form header
	if !allowedMimeTypes[header.Header.Get("Content-Type")] {
		http.Error(w, "invalid file type", http.StatusBadRequest)
		return
	}

	// Additionally validate by file extension as a secondary check
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" && ext != ".webp" {
		http.Error(w, "invalid file type", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(avatarDir, header.Filename)
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

Alternatively, use `http.DetectContentType()` to inspect the file's magic bytes instead of relying solely on the client-supplied Content-Type header:

```go
// Read a small sample to detect actual file type
buf := make([]byte, 512)
n, _ := file.Read(buf)
detectedType := http.DetectContentType(buf[:n])
if !allowedMimeTypes[detectedType] {
	http.Error(w, "invalid file type", http.StatusBadRequest)
	return
}
file.Seek(0, 0) // Reset for subsequent io.Copy()
```

## Explanation

The vulnerability exists because the code uploads any file without type validation. An attacker can upload executable files (.php, .exe, .jar, .sh, etc.) to the avatars directory and, depending on web server configuration, cause them to execute.

The fix enforces a whitelist of permitted MIME types and file extensions before writing. The MIME type check uses the `Content-Type` header from the multipart form (fast but client-controlled), while the extension check provides a secondary defence. For maximum security, `http.DetectContentType()` inspects the file's actual byte signature (magic bytes) to confirm the file is genuinely an image, defeating attempts to bypass with a renamed executable.

This ensures only image files are stored and served, preventing arbitrary code execution. The check happens before `os.Create()` to avoid writing rejected files to disk.
