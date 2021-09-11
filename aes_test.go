package aes

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"testing"
)

func TestSample(t *testing.T) {
	plaintext := []byte("123456")     // 待加密的数据
	key := []byte("9a8f748c00ebc70e") // 加密的密钥
	log.Println("原文：", string(plaintext))

	log.Println("------------------ CBC模式 --------------------")
	ciphertext, _ := AESEncryptCBC(plaintext, key)
	log.Println("密文(hex)：", hex.EncodeToString(ciphertext))
	log.Println("密文(base64)：", base64.StdEncoding.EncodeToString(ciphertext))
	plaintext, _ = AESDecryptCBC(ciphertext, key)
	log.Println("解密结果：", string(plaintext))

	log.Println("------------------ ECB模式 --------------------")
	ciphertext, _ = AESEncryptECB(plaintext, key)
	log.Println("密文(hex)：", hex.EncodeToString(ciphertext))
	log.Println("密文(base64)：", base64.StdEncoding.EncodeToString(ciphertext))
	plaintext, _ = AESDecryptECB(ciphertext, key)
	log.Println("解密结果：", string(plaintext))

	log.Println("------------------ CFB模式 --------------------")
	ciphertext, _ = AESEncryptCFB(plaintext, key)
	log.Println("密文(hex)：", hex.EncodeToString(ciphertext))
	log.Println("密文(base64)：", base64.StdEncoding.EncodeToString(ciphertext))
	plaintext, _ = AESDecryptCFB(ciphertext, key)
	log.Println("解密结果：", string(plaintext))
}
