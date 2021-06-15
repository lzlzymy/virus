package fileTransfer

import (
	"fmt"
	"io"
	"net"
	"os"
)

func SendFile(path string) {

	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Println("os.Stat err:", err)
		return
	}

	conn, err := net.Dial("tcp", "127.0.0.1:8005")
	if err != nil {
		fmt.Println("net.Dial err:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte(fileInfo.Name()))
	if err != nil {
		fmt.Println("conn.Write err:", err)
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
