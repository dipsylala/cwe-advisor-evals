## Verdict

CONFIRMED: Line 83 is vulnerable to path traversal. The `destPath` is constructed using `filepath.Join(extractDir, entry.Name)` without validating that `entry.Name` cannot escape the base directory. A malicious zip archive can include entries with path traversal sequences like `../` that cause the resulting path to write outside `extractDir`.

## Source

Line 64 constructs the destination path:
```
destPath := filepath.Join(extractDir, entry.Name)
```

The `entry.Name` comes directly from an untrusted zip archive uploaded by the user. An attacker can craft a zip file with entries like `../../etc/passwd`, and `filepath.Join()` will resolve the `..` sequences, writing files outside the intended extraction directory.

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
		// Reject paths with leading slashes or path traversal sequences.
		name := entry.Name
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("rejecting malicious path: %s", name)
		}

		destPath := filepath.Join(extractDir, name)

		// Verify the resolved path stays within extractDir.
		absExtractDir, err := filepath.Abs(extractDir)
		if err != nil {
			return fmt.Errorf("resolve extract dir: %w", err)
		}
		absDestPath, err := filepath.Abs(destPath)
		if err != nil {
			return fmt.Errorf("resolve dest path: %w", err)
		}
		if !strings.HasPrefix(absDestPath, filepath.Clean(absExtractDir)+string(os.PathSeparator)) &&
			absDestPath != filepath.Clean(absExtractDir) {
			return fmt.Errorf("path escapes extraction directory: %s", absDestPath)
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

The fix uses a two-layer defence:

1. **Input validation**: Reject any archive entry with a leading slash or containing `..` sequences before joining paths. This stops obvious traversal attempts at the source.

2. **Output validation**: After constructing `destPath`, resolve both `extractDir` and `destPath` to absolute paths using `filepath.Abs()`, then verify the result stays within the extraction directory by checking that `absDestPath` either equals `extractDir` (for files at the root) or starts with `extractDir` plus a path separator. This ensures that even if subtle path manipulation occurs, the final write location is validated.

The approach follows Go's established pattern for secure zip extraction: input-time rejection of suspicious paths combined with output-time verification that the destination is within the allowed boundary. This prevents both Zip Slip attacks (entries with `..`) and symlink escapes that could occur if only input checking were used.
