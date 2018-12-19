# CryptUtil

[![Travis](https://travis-ci.org/festum/cryptutil.svg?branch=master)](https://travis-ci.org/festum/cryptutil) [![Go Report Card](https://goreportcard.com/badge/github.com/festum/cryptutil)](https://goreportcard.com/report/github.com/festum/cryptutil)

A go utility collection for encryption/hash

## Usage

AES encryption/decryption Example:

```
package main

import (
	"fmt"
	"github.com/festum/cryptutil"
)

func main() {
	c := cryptutil.cryptor{}
	c.Init()

	sampleText := "Sample text"
	encryptedText, err := c.Encrypt([]byte(sampleText))
	if err != nil {
		fmt.Println(err)
	}
	decryptedText, err := c.Decrypt(encryptedText)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Decypted text: %s\n", decryptedText)
}
```
