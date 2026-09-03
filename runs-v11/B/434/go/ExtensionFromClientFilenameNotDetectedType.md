## Verdict

exploitable

## Source

`fileHeader.Filename` from the multipart form header (client-supplied)

## Fix

**Vulnerable code (line 66):**
```go
storedName += filepath.Ext(fileHeader.Filename)
```

**Fixed code:**
```go
// Map detected content types to safe file extensions
var ext = map[string]string{
	"image/png":       ".png",
	"image/jpeg":      ".jpg",
	"application/pdf": ".pdf",
}

// Use the detected type to derive the extension, not the client-supplied filename
storedName += ext[detectedType]
```

## Explanation

The vulnerability exists because the code validates the file's actual content type with `http.DetectContentType()` but then appends the client-supplied extension from `fileHeader.Filename` to the stored filename. An attacker can upload a PHP or shell script file with a valid image magic byte prefix that passes the `allowedContentTypes` check, but the stored file will carry the original dangerous extension (e.g. `.php`). The fix replaces the client-supplied extension with one derived from the detected content type through a fixed allowlist map. This ensures the extension always matches the verified content type and prevents an attacker from choosing the stored filename's extension.

## Behaviour changes

The extension appended to the stored filename now comes from a server-controlled map keyed by the detected content type rather than from the client-supplied `FileHeader.Filename`. This changes behaviour only for files where the client's declared extension differs from the detected type—the common attack case—and ensures the stored file extension reflects its verified content. The stored filename is still generated securely with random bytes; only the extension source changes.
