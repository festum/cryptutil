package aes

import (
	"fmt"
	"testing"
)

func TestInit(t *testing.T) {
	c := Cryptor{}
	if err := c.Init(); err != nil {
		t.Errorf("Init failed")
	}

	if _, err := c.readKey(); err != nil {
		t.Errorf("Not able read key")
	}

	if c.block == nil {
		t.Errorf("No cipher block")
	}
}

func TestCryption(t *testing.T) {
	c := Cryptor{}
	sample := "exampleplaintext"

	enc, err := c.Encrypt([]byte(sample))
	if err != nil {
		t.Errorf(fmt.Sprintf("Encryption failed: %s", err.Error()))
	}

	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Errorf("Decryption failed")
	}

	if string(dec) != sample {
		t.Errorf(fmt.Sprintf("Decrypted text is mutated %s", string(dec)))
	}

	sample = "example plain text need padding"

	enc, err = c.Encrypt([]byte(sample))
	if err != nil {
		t.Errorf(fmt.Sprintf("Encryption failed: %s", err.Error()))
	}

	dec, err = c.Decrypt(enc)
	if err != nil {
		t.Errorf("Decryption failed")
	}

	if string(dec) != sample {
		t.Errorf(fmt.Sprintf("Decrypted text is mutated %s", string(dec)))
	}
}
