package avatarupload

import (
	"io"
	"os"
	"path/filepath"
)

type AvatarStore struct {
	Dir string
}

func (s *AvatarStore) Save(filename string, file io.Reader) (string, error) {
	target := filepath.Join(s.Dir, filename)
	out, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}

	return filename, nil
}
