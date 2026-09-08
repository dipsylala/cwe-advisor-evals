## Verdict

Confirmed. `extractBundle` joins the attacker-controlled `entry.Name` from each zip entry onto `extractDir` with `filepath.Join` and never checks that the resulting path stays inside `extractDir` before creating directories and writing the file. A crafted zip entry name such as `../../etc/cron.d/evil` or an absolute path resolves outside the intended extraction directory (a classic "Zip Slip"), letting an authenticated uploader write or overwrite arbitrary files reachable by the server process.

## Source

`entry.Name` for each `*zip.File` in `reader.File`, read from the zip archive opened from the user-uploaded file (`ImportHandler` -> `r.FormFile("bundle")` -> temp file -> `extractBundle(tmp.Name())`). This value is attacker-controlled: it comes from the central directory of a zip file the signed-in user supplies, and `archive/zip` does not sanitize or restrict it.

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

	cleanExtractDir := filepath.Clean(extractDir)

	for _, entry := range reader.File {
		destPath := filepath.Join(extractDir, entry.Name)

		// Reject any entry whose resolved path escapes extractDir (Zip Slip):
		// a cleaned join must land either exactly on extractDir or strictly
		// beneath it, which also catches absolute paths and "../" traversal
		// baked into entry.Name.
		if destPath != cleanExtractDir && !strings.HasPrefix(destPath, cleanExtractDir+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in archive entry %q", entry.Name)
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

`filepath.Join(extractDir, entry.Name)` cleans the result (collapsing `..` segments arithmetically) but does not stop the final path from resolving above `extractDir` when `entry.Name` contains enough `../` segments, and it does not reject an absolute path in `entry.Name` either (`filepath.Join` treats it as just another path component, but a zip entry name starting with `/` combined with certain traversal sequences, or a Windows-style drive path on other platforms, is exactly the shape Zip Slip scanners flag). The added check computes the joined, cleaned destination path once and requires it to be either equal to the cleaned `extractDir` or have `extractDir + os.PathSeparator` as a strict prefix before any directory is created or any file is written. This rejects traversal and absolute-path entries up front with a clear error, while leaving every legitimate entry (files and subdirectories nested under `extractDir`) unaffected. The check is placed before both the directory-creation and file-creation branches so a malicious entry cannot even cause `os.MkdirAll` to create attacker-chosen directories outside the sandbox.
