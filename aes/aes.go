package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type cryptor struct {
	keyPath string
	block   cipher.Block
}

func (c *cryptor) Init() error {
	if c.keyPath == "" {
		c.keyPath = "./aes.key"
	}
	if c.block != nil {
		return nil
	}

	aesKey, err := c.readKey()
	if err != nil {
		err = nil
		//Create a new key
		aesKey = make([]byte, 16)
		if _, err := rand.Read(aesKey); err != nil {
			return fmt.Errorf("Failed to read new random key: %s", err)
		}
		block := &pem.Block{
			Type:  "AES KEY",
			Bytes: aesKey,
		}
		filename := fmt.Sprintf(c.keyPath)
		err := ioutil.WriteFile(filename, pem.EncodeToMemory(block), 0644)
		if err != nil {
			return fmt.Errorf("Failed in saving key to %s: %s", filename, err)
		}
	}
	c.block, err = aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("Failed to create the AES cipher: %s", err)
	}
	return nil
}

func (c *cryptor) Encrypt(src []byte) ([]byte, error) {
	if c.block == nil {
		if err := c.Init(); err != nil {
			return nil, err
		}
	}
	src = pkcs7Padding(src)
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	ciphertext := make([]byte, aes.BlockSize+len(src))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("Failed to read through IV: %s", err)
	}

	cbc := cipher.NewCBCEncrypter(c.block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], src)

	return ciphertext, nil
}

func (c *cryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Ciphertext is too short")
	}
	if c.block == nil {
		if err := c.Init(); err != nil {
			return nil, err
		}
	}

	iv := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("Ciphertext is not a multiple of the block size")
	}

	cbc := cipher.NewCBCDecrypter(c.block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	origin, err := pkcs7UnPadding(ciphertext)
	if err != nil {
		return nil, err
	}

	return origin, nil
}

func pkcs7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func (c cryptor) readKey() ([]byte, error) {
	key, err := ioutil.ReadFile(c.keyPath)
	if err != nil {
		return key, err
	}
	block, _ := pem.Decode(key)
	return block.Bytes, nil
}
