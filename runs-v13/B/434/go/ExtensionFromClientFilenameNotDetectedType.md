## Verdict
CONFIRMED — CWE-434 unrestricted file upload. Line 66 derives the stored filename extension from the client-supplied `fileHeader.Filename` via `filepath.Ext()` instead of from the detected content type. An attacker can upload a file with any extension (`.exe`, `.php`, `.sh`) provided the first 512 bytes match an allowed MIME type signature; the generated name will carry the attacker's extension, making it executable when served back or accessed directly.

## Source
Line 66:
```go
storedName += filepath.Ext(fileHeader.Filename)
```

The code correctly validates the actual file content using `http.DetectContentType(buf[:n])` and allowlist-checks the result, but then ignores the detected type when choosing the stored extension. The extension is what decides how the file is interpreted by the server or client on retrieval, so it must come from the detection result, not the client-supplied filename.

## Fix
Create a fixed map from detected MIME types to safe extensions. Use the allowlist-checked detected type to look up the correct extension, not the client's filename:

```go
// Map detected content types to safe, fixed extensions
var typeToExtension = map[string]string{
	"image/png":       ".png",
	"image/jpeg":      ".jpg",
	"application/pdf": ".pdf",
}

// ... after the allowlist check ...

// Generate a random, unpredictable base name for the stored file.
randBytes := make([]byte, 16)
if _, err := rand.Read(randBytes); err != nil {
	http.Error(w, "internal error", http.StatusInternalServerError)
	return
}
storedName := hex.EncodeToString(randBytes)

// Use the detected type to choose the extension, not the client filename
ext, ok := typeToExtension[detectedType]
if !ok {
	// Fallback: should not reach here if allowlist check above is correct
	http.Error(w, "unsupported file type", http.StatusUnprocessableEntity)
	return
}
storedName += ext
```

Replace line 66 with a lookup in the type-to-extension map.

## Explanation
The CWE-434 guidance states: "Derive the stored *extension* from the detected type through a fixed `mime -> ext` allowlist map: the extension is what decides how the file is later served, so a generated name carrying the client's original suffix still lets the attacker choose the half that matters."

The current code accepts uploads only if their actual content is PNG, JPEG, or PDF (verified via `http.DetectContentType`), but then appends whatever extension the attacker supplied in the filename. This creates a polyglot risk: an attacker uploads a file with valid PNG magic bytes followed by executable code, naming it `image.php`. The content check passes, the name is randomized to `a1b2c3d4e5f6g7h8.php`, and when the file is served back via a handler that determines the MIME type by extension, it executes as PHP.

The fix breaks the taint by deriving the extension from the allowlist-validated detected type, not the attacker-controlled input. The extension now matches the actual content, making it safe to serve under the generated name.

## Behaviour changes
- Files are now stored with extensions matching their actual content type, not the client-supplied filename
- `typeToExtension` map values must remain in sync with the `allowedContentTypes` allowlist keys; if a new type is added to the allowlist, add a corresponding entry to the extension map or remove the type from the allowlist
- Callers that rely on retrieving files by the original filename will break; the fix returns the generated name in the response (as the code already does via `fmt.Fprintf(w, "%s", storedName)`), so clients must store that returned name and use it for retrieval
- If a matching entry does not exist in `typeToExtension` for a type that passed the allowlist (should not happen with this code structure), an extra guard is added to catch the mismatch; in production, ensure the map and allowlist are always kept in sync
