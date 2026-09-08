## Verdict

Confirmed. The handler decides whether an uploaded avatar is acceptable by reading the client-supplied multipart `Content-Type` header (`header.Header.Get("Content-Type")`), which is attacker-controlled and travels in the same request as the file bytes. An attacker can upload any file - including an executable script - while labeling the part `image/png` or `image/jpeg`, defeating the check entirely. The file is then written to disk under the attacker-supplied filename (`header.Filename`), so the extension (and therefore how the file may later be interpreted or served) is also attacker-controlled.

## Source

`avatar_handler.go`, `UploadAvatarHandler`: the multipart field named `avatar`, specifically `header.Header.Get("Content-Type")` (attacker-controlled MIME label) and `header.Filename` (attacker-controlled name/extension), both flowing unchecked into `store.Save(header.Filename, file)` in `avatar_store.go`, which writes the bytes to `filepath.Join(s.Dir, filename)`.

## Fix

### File: avatar_handler.go
```go
package avatarupload

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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

		// Determine the real file type from its content, not from the
		// client-supplied Content-Type header, which is attacker-controlled.
		sniff := make([]byte, 512)
		n, err := io.ReadFull(file, sniff)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}
		sniff = sniff[:n]

		var ext string
		switch http.DetectContentType(sniff) {
		case "image/png":
			ext = ".png"
		case "image/jpeg":
			ext = ".jpg"
		default:
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Reassemble the stream: the sniffed prefix plus the remainder of the file.
		content := io.MultiReader(bytes.NewReader(sniff), file)

		// Never store the file under an attacker-supplied name/extension; generate
		// our own name using only the extension that matches the verified content.
		name, err := randomFilename(ext)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		storedName, err := store.Save(name, content)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}

func randomFilename(ext string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf) + ext, nil
}
```

## Explanation

The original check trusted `header.Header.Get("Content-Type")`, a value the uploading client sets on the multipart part itself and can set to anything regardless of the actual bytes that follow - it proves nothing about the file's real type. The fix instead reads the first 512 bytes of the uploaded content and classifies it with `http.DetectContentType`, which implements content sniffing over the actual byte stream (magic numbers/signatures), the same mechanism Go's standard library uses to identify real image data. Only `image/png` and `image/jpeg` results - a decision made from content, not from an attacker-supplied label - are accepted; everything else is rejected before any bytes reach storage.

Because `io.ReadFull` consumes bytes from the underlying multipart file to perform the sniff, the handler reassembles the full stream with `io.MultiReader` before handing it to `store.Save`, so no data is lost or duplicated.

The fix also stops passing `header.Filename` to `store.Save`. That field is attacker-controlled and previously became the on-disk filename verbatim (via `filepath.Join(s.Dir, filename)` in `avatar_store.go`), so it controlled the stored file's extension independently of whatever content-type check existed - an attacker could still have supplied `avatar.php` with a spoofed image header, or relied on path characters in the name. The handler now derives the stored filename entirely server-side: a random hex identifier plus the extension corresponding to the content type that was actually verified by sniffing. This removes attacker control over both the file's extension and its name, so a dangerous type can no longer reach storage labeled as an image, and the stored name can no longer be influenced by request data. `avatar_store.go` did not need to change, since it now only ever receives a filename the server generated.
