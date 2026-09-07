## Verdict
CONFIRMED

## Source
`fileHeader.Filename` - attacker-supplied filename from the multipart upload part headers (line 31).

## Fix
On line 66, replace the unsafe pattern that appends the client-supplied extension with a server-controlled extension derived from the detected content type.

Create a map from content type to safe extension:
```go
var contentTypeToExt = map[string]string{
	"image/png":       ".png",
	"image/jpeg":      ".jpg",
	"application/pdf": ".pdf",
}
```

Then replace line 66:
```go
// BEFORE (vulnerable):
storedName += filepath.Ext(fileHeader.Filename)

// AFTER (fixed):
storedName += contentTypeToExt[detectedType]
```

## Explanation
The handler correctly validates the file's real content type by reading leading bytes and calling `http.DetectContentType()` (lines 40-50). However, the generated filename is then extended with `filepath.Ext(fileHeader.Filename)` (line 66), which comes from the attacker's multipart part headers. An attacker can upload a polyglot file (valid image header followed by script code) with a malicious extension (e.g., `.php`, `.sh`). The content-type validation passes (detects `image/png`), but the file is stored with the attacker-chosen extension. If this directory is served by a web server configured to execute based on extension, the payload executes.

The fix establishes a server-controlled map that ties each allowlisted content type to a safe extension. The stored filename uses the extension from this map, never from the client-supplied filename, so the attacker cannot control how the stored file will be interpreted.

## Behaviour changes
- Stored filenames now receive safe, predictable extensions determined by detected content type instead of client-supplied extensions.
- All three allowlisted content types (`image/png`, `image/jpeg`, `application/pdf`) map to standard, safe extensions that match their content.
- Upload rejection of mismatched type/extension pairs (e.g., a PHP file with an image header) now occurs before storage because the client's extension is no longer used.
