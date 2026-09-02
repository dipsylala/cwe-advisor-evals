package imaging

import (
	"fmt"
	"os/exec"
)

func ResizeImage(inputPath, outputPath string) error {
	shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)

	// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
	cmd := exec.Command("sh", "-c", shellCmd)
	return cmd.Run()
}
