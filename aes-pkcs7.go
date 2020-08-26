package encryAndDecry

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

type PKCS7 struct {
	Secret []byte `json:"secret"`
}

//PKCS7 填充模式
func (p *PKCS7) pKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

//填充的反向操作，删除填充字符串
func (p *PKCS7) pKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	} else {
		unPadding := int(origData[length-1])
		return origData[:(length - unPadding)], nil
	}
}

func (p *PKCS7) Encryption(origData []byte) (string, error) {
	cip, err := p.aesEncryption(origData)
	if err != nil {
		return "", err
	}
	str, err := p.enCipher(cip)
	if err != nil {
		return "", err
	}
	return str, nil
}

//实现AES加密
func (p *PKCS7) aesEncryption(origData []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.Secret)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = p.pKCS7Padding(origData, blockSize)
	blocMode := cipher.NewCBCEncrypter(block, p.Secret[:blockSize])
	ciphertext := make([]byte, len(origData))
	blocMode.CryptBlocks([]byte(ciphertext), origData)
	return ciphertext, nil
}

func (p *PKCS7) Decrypt(ciphertext string) (string, error) {
	cip, err := p.deCipher(ciphertext)
	if err != nil {
		return "", err
	}
	b, err := p.aesDeCrypt(cip)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

//实现解密
func (p *PKCS7) aesDeCrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.Secret)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, p.Secret[:blockSize])
	origData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(origData, ciphertext)
	origData, err = p.pKCS7UnPadding(origData)
	if err != nil {
		return nil, err
	}
	return origData, err
}

//加密base64
func (p *PKCS7) enCipher(cip []byte) (string, error) {
	result, err := p.aesEncryption(cip)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(result)), err
}

//解密base64
func (p *PKCS7) deCipher(pwd string) ([]byte, error) {
	cipByte, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		return nil, err
	}
	return p.aesDeCrypt(cipByte)
}
