package avatars

import (
	"os"
	"path/filepath"
)

func ReadAvatarBytes(originalFilename string) ([]byte, error) {
	return os.ReadFile(filepath.Join(storageDir, originalFilename))
}
