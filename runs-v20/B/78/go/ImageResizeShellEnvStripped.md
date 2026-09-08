## Verdict

exploitable

## Source

`inputPath` and `outputPath`, the two parameters of `ResizeImage(inputPath, outputPath string) error` (resize.go, line 8). Nothing in this file constrains or validates either value before it is used, and the finding confirms both are attacker-influenced (e.g. an upload path or filename supplied by a caller). Both flow unmodified into `fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)` (line 9), which builds a single shell command line by direct string interpolation. That string is handed to `exec.Command("sh", "-c", shellCmd)` (line 12) and executed with `cmd.Run()` (line 13) - the sink. Any shell metacharacter in either path (`;`, `|`, `&&`, `$()`, backticks, etc.) is interpreted by `sh`, not treated as literal argument data - classic OS command injection. Sink contract: returns only an `error` (from `cmd.Run()`); no stdout/stderr is captured or exposed; the target binary (`convert`), its flags, and the shell itself are all implicit and unvalidated.

## Fix

Resizing an image with ImageMagick's `convert` is not a case where shelling out is the purpose of the code - it is a stand-in for an operation Go's standard library (plus the Go team's `golang.org/x/image` module) performs natively: decode, scale, re-encode. Per the CWE-78 guidance, the primary remediation here is eliminating command execution entirely rather than trying to parameterize the shell call.

### File: resize.go

```go
package imaging

import (
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/image/draw"
)

const (
	maxWidth  = 800
	maxHeight = 600
)

func ResizeImage(inputPath, outputPath string) error {
	src, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer src.Close()

	img, _, err := image.Decode(src)
	if err != nil {
		return fmt.Errorf("decode image: %w", err)
	}

	bounds := img.Bounds()
	srcW, srcH := bounds.Dx(), bounds.Dy()
	scale := float64(maxWidth) / float64(srcW)
	if hScale := float64(maxHeight) / float64(srcH); hScale < scale {
		scale = hScale
	}
	dstW := int(float64(srcW)*scale + 0.5)
	dstH := int(float64(srcH)*scale + 0.5)
	if dstW < 1 {
		dstW = 1
	}
	if dstH < 1 {
		dstH = 1
	}

	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, bounds, draw.Over, nil)

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	switch strings.ToLower(filepath.Ext(outputPath)) {
	case ".jpg", ".jpeg":
		err = jpeg.Encode(out, dst, &jpeg.Options{Quality: 92})
	case ".png":
		err = png.Encode(out, dst)
	default:
		err = fmt.Errorf("unsupported output format %q", filepath.Ext(outputPath))
	}
	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	return nil
}
```

This adds `golang.org/x/image` as a module dependency (`go get golang.org/x/image`, then `go mod tidy`); confirm the resolved version against your SCA/dependency tooling before merging. `image`, `image/gif`, `image/jpeg`, `image/png`, `os`, `path/filepath`, `strings`, and `fmt` are all Go standard library.

## Explanation

`os/exec` and the shell are removed completely: `inputPath` and `outputPath` are now used only as filesystem paths passed to `os.Open`/`os.Create`, so shell metacharacters in either value have no interpreter to reach - the injection point is gone, not just narrowed. The resize itself is done with `image.Decode` (format auto-detected the same way `convert` infers it, for PNG/JPEG/GIF input) and `golang.org/x/image/draw`'s `CatmullRom` scaler, a high-quality resampling filter comparable to ImageMagick's default. The target size is computed to fit within 800x600 while preserving aspect ratio, matching the behavior of ImageMagick's `-resize 800x600` (a bare `WxH` geometry without `!`/`^` scales to fit the box rather than stretching to it exactly, and can enlarge as well as shrink) rather than distorting the image to an exact 800x600. Output format is chosen from `outputPath`'s extension (`.jpg`/`.jpeg` or `.png`), mirroring `convert`'s extension-based output selection. The function's signature and return contract (`error` only, nothing captured from a subprocess) are unchanged.

Verification: `go build ./...` and `go vet ./...` against the fixed file in a scratch module (with `golang.org/x/image/draw` fetched via `go get`) both completed with no errors or warnings. A functional test additionally confirmed a 1600x400 PNG resizes to 800x200 (aspect preserved, longer dimension capped at 800) and that passing `"in.png; touch /tmp/pwned"` as `inputPath` fails as a plain file-not-found error rather than being interpreted by a shell.

## Behaviour changes

- Format support narrows: the fix decodes PNG, JPEG, and GIF, and encodes PNG or JPEG, versus ImageMagick's much broader format matrix (TIFF, WebP, BMP, HEIC, etc.). An input or requested output outside that set now fails with an explicit `error` instead of `convert` handling it - reason: no single Go standard-library/`x/image` API covers ImageMagick's full format list without materially larger scope; the common raster formats are covered.
- JPEG output quality is fixed at `92` (`jpeg.Options{Quality: 92}`) since Go's JPEG encoder has no equivalent to ImageMagick's per-source quality inference - reason: chosen to approximate ImageMagick's typical default rather than Go's own encoder default (75), documented here as an assumption since exact parity with `convert`'s quality selection isn't achievable.
- The external dependency on the `convert` binary being installed and on `PATH` is replaced by the `golang.org/x/image` module dependency - reason: intrinsic to eliminating the shell-out, and this module is maintained by the Go team.
- No change to the function signature, its `error`-only return, or what it does on failure (I/O or decode/encode errors are wrapped and returned, nothing is written to stdout/stderr or leaked that the original discarded).
