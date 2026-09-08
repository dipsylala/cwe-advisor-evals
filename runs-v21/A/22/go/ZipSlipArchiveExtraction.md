## Verdict

The code is vulnerable to Zip Slip (CWE-22: Path Traversal). Archive entries with names like `../../etc/passwd` or `/etc/passwd` can escape the intended extraction directory and overwrite arbitrary files on the system.

## Source

The vulnerability is in the `extractBundle()` function at line 64:

```go
destPath := filepath.Join(extractDir, entry.Name)
```

The `entry.Name` comes directly from the zip archive and can contain path traversal sequences (`..`, absolute paths) that allow files to be written outside `extractDir`.

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
		// Sanitize the entry name to prevent directory traversal.
		// filepath.Clean() resolves .. and . sequences; reject entries
		// that try to escape or use absolute paths.
		cleanedName := filepath.Clean(entry.Name)
		if strings.HasPrefix(cleanedName, "..") || strings.HasPrefix(cleanedName, "/") {
			return fmt.Errorf("invalid archive entry path: %s", entry.Name)
		}

		destPath := filepath.Join(extractDir, cleanedName)

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

The fix adds path validation before constructing the destination path:

1. **`filepath.Clean(entry.Name)`**: Normalizes the entry name by resolving `.` and `..` sequences. For example, `foo/../../../etc/passwd` becomes `../../../etc/passwd`.

2. **Check for escape attempts**: Rejects entries where the cleaned name starts with `..` (directory traversal) or `/` (absolute path). Either condition indicates an attempt to write outside `extractDir`.

3. **Import `strings`**: Added to the imports for the `HasPrefix()` function used in validation.

The validation happens before calling `filepath.Join()`, so even a malicious archive cannot escape the extraction boundary. Files are only extracted if their paths resolve to a location within `extractDir`.
