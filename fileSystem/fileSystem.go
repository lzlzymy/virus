package fileSystem

import (
	"os"
	"path/filepath"
	"strings"
)

func GetAllFile(itself string) (files []string) {
	pwd, _ := os.Getwd()

	filepath.Walk(pwd, func(path string, info os.FileInfo, err error) error {
		ok1 := strings.HasSuffix(path, itself)
		ok2 := strings.HasSuffix(path, ".enc")
		if !ok1 && !ok2 {
			s, _ := os.Stat(path)
			if !s.IsDir() {
				files = append(files, path)
			}
		}
		return nil
	})

	return files
}
