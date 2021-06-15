package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var public_Key1 = []byte("-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3nXmd7bRWeOS3LOktKsm\nnAltGP6cnKvyMsb8VjTpTUe1Puz2hcSg106L64D9mnXQI2dnAgz5RysDd31eC770\ntFgFsQOo8CqEu4xN0YktBsfvl20VVvc1yRY9TcXtWKNXckNVkrGJTNtyOPwTnvLw\nhbKq6iNpuJm4Jv3u0Q/ZgyAk1ae1rnBN3KLgeHHXWs/bDvGfPKp/3oBIqFQn1VOq\n+qddElI2UhyVhRv7+mTuvDYStKhW8f7Yd8RDIwqIdmUHaH4+dF6BtlcDquP9gyAe\nHXXqxKXl/i205LZzXCDulfsYWhALW+ntCukei7GCb6umZsuLbH81ZJfQwKHqu+MP\nSD5FHIuppaOb/AV/o0ynGngvFwHHKSqyDjZ+Y8++D+J0B77vp265xt/I+GVUSK+r\nUJj+CPduVTijgU+pG/GF4qxbSuJQNhtMZk2HgCpVdAovhfXMfRui7CvKhCr9qvpb\nNtGmimkAKlIihQrVNGFkebkOPj6+1RAm/tlz472JQbXdPsTwXGFq5BIWqNn+0f6R\n2h9qj2A/jraLJCF0TyVwvlk1N5S+i5Ei3dlueK2g21wmlr9OrMmn5lecQxvAOhg2\nMV+40p0Ow3LY8Uu7HxbCYtdFiy7YrqZaag5uNfWH2YP9MfeKR5LxH0DlMi6WMQN7\nDaAr0F7ISTGk+6a0CGMZP0kCAwEAAQ==\n-----END PUBLIC KEY-----\n")

func GenRsaKey() (prvkey, pubkey []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
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

func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(public_Key1)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

//
//func RsaDecrypt(ciphertext []byte) ([]byte, error) {
//	//解密
//	block, _ := pem.Decode(privateKey)
//	if block == nil {
//		return nil, errors.New("private key error!")
//	}
//	//解析PKCS1格式的私钥
//	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
//	if err != nil {
//		return nil, err
//	}
//	// 解密
//	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
//}

func Init() {
	private_Key2, public_Key2 := GenRsaKey()
	fmt.Println(string(public_Key1))
	fmt.Println(string(private_Key2))
	fmt.Println(string(public_Key2))
	data, _ := RsaEncrypt([]byte("test dataΩ......"))
	fmt.Println(data)
}
