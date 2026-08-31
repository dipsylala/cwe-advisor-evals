## Verdict

CWE-434 confirmed. The handler accepts file uploads without validating the file type, allowing an attacker to upload and execute arbitrary code.

## Source

Line 30-32. The filename from `header.Filename` (user-controlled) is used directly in `filepath.Join()` and `os.Create()` without type validation. Since the directory is served via `http.FileServer` (line 14), uploaded executables or scripts can be triggered by the server.

## Fix

```go
package main

import (
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

	// Validate file type by extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowedExts := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true}
	if !allowedExts[ext] {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
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

## Explanation

The fix adds an allowlist check on the file extension before accepting the upload. Only `.jpg`, `.jpeg`, `.png`, and `.gif` files are permitted. Files with other extensions (e.g., `.exe`, `.sh`, `.php`) are rejected with a 400 error. This prevents upload and potential execution of arbitrary code via the FileServer. For a stricter defense, validate MIME type via `http.DetectContentType()` on the file content (first 512 bytes) in addition to the extension check.
