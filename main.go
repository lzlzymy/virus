package main

import (
	"./fileSystem"
	"fmt"
)

func main() {
	fmt.Println("请输入需要扫描的文件：")
	var path string
	fmt.Scan(&path)
	fileSystem.GetAllFile(path)
}
