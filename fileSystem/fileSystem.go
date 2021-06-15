package fileSystem

import (
	"os"
	"path/filepath"
	"strings"
)

func GetAllFile() (files []string) {
	pwd, _ := os.Getwd()

	filepath.Walk(pwd, func(path string, info os.FileInfo, err error) error {
		ok := strings.HasSuffix(path, "virus.exe")
		if !ok {
			s, _ := os.Stat(path)
			if !s.IsDir() {
				files = append(files, path)
			}
		}
		return nil
	})

	return files
}
