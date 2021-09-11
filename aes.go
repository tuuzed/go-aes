package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// =================== CBC ======================

func AESEncryptCBC(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	blockSize := block.BlockSize()                              // 获取秘钥块的长度
	plaintext = pkcs5Padding(plaintext, blockSize)              // 补全码
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) // 加密模式
	ciphertext = make([]byte, len(plaintext))                   // 创建数组
	blockMode.CryptBlocks(ciphertext, plaintext)                // 加密
	return ciphertext, nil
}
func AESDecryptCBC(ciphertext []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key) // 分组秘钥
	if err != nil {
		return
	}
	blockSize := block.BlockSize()                              // 获取秘钥块的长度
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) // 加密模式
	plaintext = make([]byte, len(ciphertext))                   // 创建数组
	blockMode.CryptBlocks(plaintext, ciphertext)                // 解密
	plaintext = pkcs5UnPadding(plaintext)                       // 去除补全码
	return plaintext, nil
}
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// =================== ECB ======================

func AESEncryptECB(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(generateKey(key))
	if err != nil {
		return
	}
	length := (len(plaintext) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, plaintext)
	pad := byte(len(plain) - len(plaintext))
	for i := len(plaintext); i < len(plain); i++ {
		plain[i] = pad
	}
	ciphertext = make([]byte, len(plain))
	// 分组分块加密
	for bs, be := 0, block.BlockSize(); bs <= len(plaintext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(ciphertext[bs:be], plain[bs:be])
	}
	return ciphertext, nil
}
func AESDecryptECB(ciphertext []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(generateKey(key))
	if err != nil {
		return
	}
	plaintext = make([]byte, len(ciphertext))
	// 分组分块解密
	for bs, be := 0, block.BlockSize(); bs < len(ciphertext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
	}
	trim := 0
	if len(plaintext) > 0 {
		trim = len(plaintext) - int(plaintext[len(plaintext)-1])
	}
	return plaintext[:trim], nil
}
func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// =================== CFB ======================

func AESEncryptCFB(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}
func AESDecryptCFB(ciphertext []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}
