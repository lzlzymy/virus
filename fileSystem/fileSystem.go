package fileSystem

import (
	"github.com/fcharlie/buna/debug/pe"
	"os"
	"path/filepath"
	"strings"
)

func GetAllFile(itself string) (files1 []string, files2 []string) {
	pwd, _ := os.Getwd()

	filepath.Walk(pwd, func(path string, info os.FileInfo, err error) error {
		ok1 := strings.HasSuffix(path, itself)
		ok2 := strings.HasSuffix(path, ".enc")
		if !ok1 && !ok2 {
			s, _ := os.Stat(path)
			if !s.IsDir() {
				_, err := pe.Open(path)
				if err != nil {
					files1 = append(files1, path)
				}
				files2 = append(files2, path)
			}
		}
		return nil
	})

	return files1, files2
}
