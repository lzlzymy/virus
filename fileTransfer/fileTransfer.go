package fileTransfer

import (
	"io"
	"net"
	"os"
)

func SendFile(path string) {

	fileInfo, err := os.Stat(path)
	if err != nil {
		return
	}

	conn, err := net.Dial("tcp", "127.0.0.1:8005")
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte(fileInfo.Name()))
	if err != nil {
		return
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}

	defer f.Close()

	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				return
			}
		}
		conn.Write(buf[:n])
	}
}
