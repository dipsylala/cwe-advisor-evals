## Verdict

Confirmed. CWE-22 (Zip Slip variant) at `extractBundle`, line 83 (`os.Create(destPath)`).

## Source

`entry.Name` from each `*zip.File` in `reader.File`, where `reader` is opened from the user-uploaded archive (`ImportHandler` -> `r.FormFile("bundle")` -> buffered to a temp file -> `extractBundle(tmp.Name())` -> `zip.OpenReader`). Archive entry names are attacker-controlled: nothing in the zip format constrains them, and the code performs no validation before use.

## Fix

### File: ZipSlipArchiveExtraction.go

```go
// Package archiveimport implements an HTTP endpoint that lets a signed-in
// user upload a zip bundle of plugin assets, which the server extracts into
// a per-tenant working directory for later processing.
package archiveimport

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const extractDir = "/var/lib/pluginhost/import"

// ImportHandler receives a multipart-uploaded zip archive, saves it to a
// temp file, and extracts every entry into extractDir so the plugin loader
// can pick the files up on its next scan.
func ImportHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("bundle")
	if err != nil {
		http.Error(w, "missing bundle field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "plugin-bundle-*.zip")
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := io.Copy(tmp, file); err != nil {
		http.Error(w, "failed to buffer upload", http.StatusInternalServerError)
		return
	}

	if err := extractBundle(tmp.Name()); err != nil {
		http.Error(w, fmt.Sprintf("extraction failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// extractBundle unpacks every file entry in the archive at zipPath into
// extractDir, preserving the directory structure recorded in the archive.
func extractBundle(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer reader.Close()

	for _, entry := range reader.File {
		destPath := filepath.Join(extractDir, entry.Name)

		// Zip Slip: entry.Name is untrusted and may contain ".." or an
		// absolute path. filepath.Join cleans the syntax but does not
		// enforce containment, so verify the resolved path is still inside
		// extractDir before any directory is created or file written.
		if destPath != extractDir && !strings.HasPrefix(destPath, extractDir+string(filepath.Separator)) {
			return fmt.Errorf("entry %s escapes extraction directory", entry.Name)
		}

		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", destPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("create parent for %s: %w", destPath, err)
		}

		src, err := entry.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", entry.Name, err)
		}

		dst, err := os.Create(destPath)
		if err != nil {
			src.Close()
			return fmt.Errorf("create %s: %w", destPath, err)
		}

		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return fmt.Errorf("write %s: %w", destPath, err)
		}

		src.Close()
		dst.Close()
	}

	return nil
}
```

## Explanation

`destPath := filepath.Join(extractDir, entry.Name)` cleans the path syntactically but does not enforce that the result stays under `extractDir` - an entry named `../../etc/cron.d/x` (or an absolute path) resolves to a location entirely outside the intended tree, and the code proceeded straight to `os.MkdirAll`/`os.Create` on that path. The fix adds a containment check immediately after the join, before either `MkdirAll` call or the `os.Create` sink: the resolved path must equal `extractDir` or have `extractDir + separator` as a prefix. Using the separator-qualified prefix (rather than a bare string prefix) avoids the classic `/var/lib/pluginhost/import-evil` false-negative, and comparing against the already-canonical `destPath` (rather than re-deriving a path later) means the value validated is the value used at both the directory-creation and file-creation sinks. A non-conforming entry aborts extraction with an error rather than silently stripping or skipping it, so the attempt surfaces instead of being hidden. No separate `..`-substring check was added, since it would be redundant with containment and would reject a legitimate entry name that merely contains `..` (e.g. `notes..v2.txt`).

Symlink-based escapes (an earlier entry creating a symlink under `extractDir` that a later entry's `MkdirAll`/`Create` then follows) are a separate hardening concern from the reported path-traversal sink and are not addressed here; `os.OpenRoot`/`os.Root` (Go 1.24+) is the recommended primitive if that threat needs to be closed as well.

Checked: every function used in the fix (`strings.HasPrefix`, `filepath.Separator`) is Go standard library, already imported (`path/filepath`) or newly imported (`strings`) in this change. Verified by compiling the fixed file with `go build` and `go vet` against a scratch module (Go 1.25.5) - both completed with no errors or warnings.

## Behaviour changes

- A zip entry whose computed destination path falls outside `extractDir` now aborts extraction with an error (`"entry %s escapes extraction directory"`), surfaced to the HTTP caller as a 500 via the existing `extractBundle` error path in `ImportHandler`. Previously such an entry would have been written outside the intended directory (or crashed on `MkdirAll`/`Create` failures for unrelated reasons). All legitimate archives - any entry whose name has no `..` traversal and is not absolute - extract exactly as before, with no change to their resulting paths.
