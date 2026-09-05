## Verdict

Exploitable. The vulnerability allows an attacker to upload a file of any type by forging the `Content-Type` header, then store it with a dangerous extension that can be executed or processed as code.

## Source

Line 21: `header.Header.Get("Content-Type")` - client-supplied multipart part header
Line 27: `header.Filename` - client-supplied multipart filename
Both are attacker-controlled and not validated by the standard library.

## Fix

**Vulnerable code** (avatar_handler.go, lines 21-27):
```go
contentType := header.Header.Get("Content-Type")
if contentType != "image/png" && contentType != "image/jpeg" {
	http.Error(w, "unsupported avatar", http.StatusBadRequest)
	return
}

storedName, err := store.Save(header.Filename, file)
```

**Fixed code** (avatar_handler.go):
```go
// Add imports: "crypto/rand", "encoding/hex", "io"

// Define allowlist mapping
var allowedTypes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
}

// In UploadAvatarHandler function, after file.Close() defer:
// Rewind to start for content detection
if _, err := file.Seek(0, io.SeekStart); err != nil {
	http.Error(w, "seek failed", http.StatusInternalServerError)
	return
}

// Sniff actual content type from file bytes
sniff := make([]byte, 512)
n, err := file.Read(sniff)
if err != nil && err != io.EOF {
	http.Error(w, "read failed", http.StatusInternalServerError)
	return
}

detected := http.DetectContentType(sniff[:n])

// Validate detected type against allowlist
ext, ok := allowedTypes[detected]
if !ok {
	http.Error(w, "unsupported file type", http.StatusBadRequest)
	return
}

// Generate random filename with allowed extension
randomBytes := make([]byte, 16)
if _, err := rand.Read(randomBytes); err != nil {
	http.Error(w, "filename generation failed", http.StatusInternalServerError)
	return
}
storedName := hex.EncodeToString(randomBytes) + ext

// Rewind file again before saving
if _, err := file.Seek(0, io.SeekStart); err != nil {
	http.Error(w, "seek failed", http.StatusInternalServerError)
	return
}

err = store.Save(storedName, file)
if err != nil {
	http.Error(w, "upload failed", http.StatusInternalServerError)
	return
}
```

**avatar_store.go** (update Save method signature to use generated filename):
```go
// No changes required - the filename is now controlled by the handler
// The store simply writes the pre-generated, validated filename
```

## Explanation

The original code trusted the client-supplied `Content-Type` header and filename extension, both of which an attacker can forge. By reading the actual file's leading bytes with `http.DetectContentType()`, the fix validates the real content type regardless of what the client claimed. The allowlist map restricts to image types only, and a fresh variable holds the canonical extension determined from the detected type, not the client's filename. The filename is generated with `crypto/rand` to prevent path traversal and to ensure a safe extension. The file is rewound before saving to capture the full content despite the sniffing reads. This eliminates the ability to disguise dangerous file types and prevents execution of uploaded scripts.

## Behaviour changes

1. **Return value change in handler**: The handler now returns the generated `storedName` instead of `header.Filename`. The caller receives `hex.EncodeToString(randomBytes) + ext` rather than the original filename. This is a breaking change for any client that relied on retrieving files by their upload name; the caller must now use the returned generated name or persist a mapping between original and stored filenames.

2. **File position side effects**: The file pointer is rewound twice (`Seek(0, io.SeekStart)`) - once after detecting content type, and again before saving. This is necessary to ensure the full content is written despite the detection read.

3. **New imports required**: `crypto/rand`, `encoding/hex`, and `io` must be imported for the fix to compile.

4. **Filename structure change**: Stored filenames are now random hex strings with a safe extension (e.g., `a1b2c3d4e5f6... .png`) instead of the user-supplied name. Callers must be updated to handle this change.

5. **No size limit enforcement in current fix**: The guidance recommends `http.MaxBytesReader` for size enforcement; this fix does not add it but should be paired with size limits at the handler entry point (e.g., `http.MaxBytesReader(w, r.Body, maxSize)` before `ParseMultipartForm`).

