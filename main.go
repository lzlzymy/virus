package main

import (
	"./encrypt"
	"./fileSystem"
	"fmt"
)

func main() {
	filePath := fileSystem.GetAllFile()
	for _, name := range filePath {
		fmt.Println(name)
	}
	encrypt.Init()
}
