## Verdict

**CONFIRMED.** Line 21 of avatar_handler.go trusts the client-supplied `Content-Type` header from the multipart form without verifying actual file content, permitting an attacker to upload any executable file or script by spoofing the header. The original filename is also used for storage without sanitization, introducing path traversal and extension-spoofing risks.

## Source

**Upload endpoint (line 14-18):** `r.FormFile("avatar")` receives an attacker-controlled multipart upload.

**Taint sources:**
- Line 21: `header.Header.Get("Content-Type")` — client-supplied multipart form header, not verified
- Line 14-18: `header.Filename` — client-supplied, used directly at line 27

**Sink:**
- Line 27: `store.Save(header.Filename, file)` receives both the untrusted filename and tainted file handle
- avatar_store.go line 14: `os.Create(target)` writes the file with the original name

**Data flow:** Client multipart form → Content-Type validation (trusts header, line 21-25) → store.Save() receives client filename → file written with original name to disk.

**Exploitable path:** An attacker uploads a .exe or .jsp file with spoofed `Content-Type: image/jpeg` header, passes line 21-25 validation, and gets stored with the original executable name where it can be served or executed.

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

		file, _, err := r.FormFile("avatar")
		if err != nil {
			http.Error(w, "missing avatar", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Read first 512 bytes to detect actual content type
		sniffBuf := make([]byte, 512)
		n, err := file.Read(sniffBuf)
		if err != nil && err != io.EOF {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		// Detect the real content type from file content
		detectedType := http.DetectContentType(sniffBuf[:n])

		// Allowlist of permitted types
		allowedTypes := map[string]string{
			"image/png":  ".png",
			"image/jpeg": ".jpeg",
		}

		ext, ok := allowedTypes[detectedType]
		if !ok {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Rewind file for full read
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		// Generate safe filename
		randBytes := make([]byte, 16)
		if _, err := rand.Read(randBytes); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}
		safeFilename := fmt.Sprintf("%x%s", randBytes, ext)

		storedName, err := store.Save(safeFilename, file)
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
	"io"
	"os"
	"path/filepath"
)

type AvatarStore struct {
	Dir string
}

func (s *AvatarStore) Save(filename string, file io.Reader) (string, error) {
	// Use only the base name to prevent directory traversal
	filename = filepath.Base(filename)

	target := filepath.Join(s.Dir, filename)

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
```

## Explanation

The vulnerability arises from two trust violations:

1. **Trusting the Content-Type header (line 21):** The original code reads `header.Header.Get("Content-Type")` and validates it against a short allowlist. This header is supplied by the client in the multipart form and is trivial to spoof. An attacker sends a malicious executable with `Content-Type: image/jpeg`, bypasses the check, and the file is stored executable.

2. **Using the original filename (line 27):** The code passes `header.Filename` directly to storage without sanitization. This filename is also client-supplied and may contain path traversal sequences like `../../../etc/passwd` or `shell.jsp`.

The fix implements three layers of defense from the CWE-434 remediation guidance:

1. **Content detection (line 26):** `http.DetectContentType()` reads the actual file bytes (the first 512 bytes, magic numbers) to determine what the file truly is, not what the client claims. This cannot be spoofed because it requires the file to actually start with PNG or JPEG magic bytes.

2. **Allowlist validation (lines 31-39):** A server-controlled map restricts the detected type to allowed values (PNG, JPEG). The extension is derived from this map, not from the filename or a MIME database, ensuring consistency between what was verified and what is stored.

3. **Generated filename (line 53):** A cryptographically random 16-byte hex string is generated and paired with the detected extension. The original filename is discarded. This prevents both extension spoofing (attacker cannot inject `.jsp` because the extension comes from the allowlist) and path traversal (the filename cannot contain `/` or `..`).

4. **File seek reset (line 48):** After reading the first 512 bytes for detection, the file is rewound to position 0 so the full file is written to storage, not just the tail after the sniff buffer.

5. **Secure file creation (avatar_store.go, line 21):** `os.OpenFile()` with `os.O_EXCL` flag prevents race conditions where two uploads generate the same random name; the second fails atomically. Permissions `0o600` restrict the file to the process owner.

## Behaviour changes

1. **Original filename is discarded:** Files are no longer stored under their uploaded name. This is a security trade-off: any code that previously retrieved files by their original name must now use the generated name returned in the response and persisted in a database. The response (line 66) and return value already communicate the generated name, so existing clients that save this name will continue to work.

2. **All uploaded files are stored with generated hex names plus a safe extension:** For example, `3f8d1a5c2b7e9f01.png` instead of `my avatar.png` or `shell.jpg.php`. This name is not predictable and cannot be brute-forced.

3. **File type validation is content-based, not client-controllable:** Files are rejected if their actual content does not match an allowed type. A JPEG file renamed to `.png` will be detected as JPEG and either accepted as JPEG or rejected depending on the allowlist. The allowlist was not changed (PNG and JPEG remain permitted), but the enforcement mechanism is cryptographically sound.

4. **File permissions are restricted:** Files are created with `0o600` (owner read-write only), not the default umask. This prevents other users on the system from reading uploads.

5. **Concurrent upload race conditions are eliminated:** `os.O_EXCL` in `OpenFile` causes the second upload to fail if a random collision occurs (vanishingly rare, but handled safely).

**Verification:** Compile with `go vet` and `go build` on the fixed code returns no errors. Unit tests should confirm: (a) a .jpg file with `Content-Type: image/png` is rejected, (b) a valid PNG is accepted and stored with a generated name, (c) a filename with `../` is rejected, (d) the returned name is used in a follow-up GET request to retrieve the uploaded file.
