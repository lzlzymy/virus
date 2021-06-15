package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func RecvFile(fileName string, conn net.Conn) {
	// 创建新文件
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Create err:", err)
		return
	}
	defer f.Close()

	// 接收客户端发送文件内容，原封不动写入文件
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Println("文件接收完毕")
			} else {
				fmt.Println("Read err:", err)
			}
			return
		}
		f.Write(buf[:n]) // 写入文件，读多少写多少
	}
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:8005")
	if err != nil {
		fmt.Println("Listen err:", err)
		return
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("Accept err:", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Read err:", err)
		return
	}
	fileName := string(buf[:n])

	RecvFile(fileName, conn)
}
