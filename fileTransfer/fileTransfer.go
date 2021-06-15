package fileTransfer

import (
	"fmt"
	"io"
	"net"
	"os"
)

func SendFile(path string, conn net.Conn) {
	// 以只读方式打开文件
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("os.Open err:", err)
		return
	}
	defer f.Close() // 发送结束关闭文件。

	// 循环读取文件，原封不动的写给服务器
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf) // 读取文件内容到切片缓冲中
		if err != nil {
			if err == io.EOF {
				fmt.Println("文件发送完毕")
			} else {
				fmt.Println("f.Read err:", err)
			}
			return
		}
		conn.Write(buf[:n]) // 原封不动写给服务器
	}
}

func main() {
	// 提示输入文件名
	fmt.Println("请输入需要传输的文件：")
	var path string
	fmt.Scan(&path)

	// 获取文件名   fileInfo.Name()
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

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("conn.Read err:", err)
		return
	}

	if "ok" == string(buf[:n]) {
		SendFile(path, conn)
	}
}
