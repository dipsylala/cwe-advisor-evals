## Verdict

True positive. `UploadAvatar` writes attacker-controlled bytes to disk under `header.Filename` with no restriction on file type, so a client can upload any content (a web shell, an executable, an HTML file for stored XSS, etc.) as an "avatar" and have it persisted verbatim under the avatars storage directory.

## Source

- `header.Filename` — the client-supplied multipart filename from `r.FormFile("avatar")`. Fully attacker-controlled, used unvalidated as the on-disk filename.
- `bytes` — the client-supplied file content read via `io.ReadAll(file)`. Never inspected before being written to disk.

Both flow directly into the sink `os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)` with no extension allowlist, no content-type check, and no filename sanitization.

## Fix

### File: avatar_upload.go
```go
package avatars

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const storageDir = "/var/app-data/avatars"

// allowedAvatarTypes maps the only file extensions avatars may be stored
// with to the MIME type that extension is expected to sniff as. Both the
// extension and the actual content are checked before a file is written.
var allowedAvatarTypes = map[string]string{
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
	".webp": "image/webp",
}

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

	// Strip any directory components so the on-disk name (and the name a
	// later lookup must reproduce) can never escape storageDir.
	safeName := filepath.Base(header.Filename)

	ext := strings.ToLower(filepath.Ext(safeName))
	expectedMIME, ok := allowedAvatarTypes[ext]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
		return
	}

	// The extension alone is attacker-supplied and easily spoofed, so
	// confirm the actual bytes sniff as the image type the extension
	// claims before anything is written to disk.
	if detected := http.DetectContentType(bytes); detected != expectedMIME {
		http.Error(w, "file content does not match its extension", http.StatusBadRequest)
		return
	}

	if err := os.WriteFile(filepath.Join(storageDir, safeName), bytes, 0o600); err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

The upload handler is the sink, so the fix stays there: it now enforces an allowlist of image extensions and, more importantly, verifies the actual file content against that extension with `http.DetectContentType` (Go's `net/http` magic-byte sniffer) rather than trusting the client-declared extension alone — a `.jpg` extension wrapping a script or executable is rejected because its sniffed content type won't be `image/jpeg`. `filepath.Base` strips any directory separators from the client-supplied name before it is ever joined into a path, closing the traversal angle on the same input.

The stored filename is deliberately kept as the sanitized *original* name (`filepath.Base(header.Filename)`) rather than replaced with a generated name such as a UUID. `ReadAvatarBytes(originalFilename)` in the companion lookup path reconstructs the storage path from that same original filename; renaming on write without also changing how lookups resolve a stored file would silently break every subsequent read (or require rewriting the lookup file, which is out of scope here and would need a persisted mapping from original name to stored name). Restricting what can be written — by extension and by sniffed content — closes the dangerous-upload finding without touching that read path or its naming contract.
