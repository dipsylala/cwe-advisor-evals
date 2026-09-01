## Verdict
CWE-434 confirmed. The code accepts arbitrary file uploads without validating file type or content, enabling an attacker to upload and execute malicious files (executables, scripts) via the `/avatars/` endpoint.

## Source
Line 30: `header.Filename` is untrusted user input from the multipart form upload, taken directly without validation.

## Fix
```go
import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const avatarDir = "./public/avatars"

// Allowlist of safe image file extensions
var allowedExtensions = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
	".webp": true,
}

func init() {
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

	// Validate file extension
	filename := filepath.Base(header.Filename) // Prevent path traversal
	ext := strings.ToLower(filepath.Ext(filename))
	
	if !allowedExtensions[ext] {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(avatarDir, filename)
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
The fix implements two controls:

1. **Extension allowlist**: Only `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp` are permitted. This prevents upload of executable or script files (.php, .go, .sh, .exe, etc.) that could be executed when accessed via the web server.

2. **Path traversal prevention**: `filepath.Base()` strips directory components from the filename (e.g., converts `../../etc/passwd` to `passwd`), preventing an attacker from escaping the avatarDir. This complements the extension check by ensuring the file lands in the expected directory.

3. **Lowercase normalization**: File extensions are compared in lowercase to prevent bypass via `.JPG` vs `.jpg`.

The rejection happens before file creation, so no dangerous files are written to disk.
