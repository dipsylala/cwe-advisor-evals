package archivelist

import (
	"context"
	"os/exec"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)
	return cmd.CombinedOutput()
}
