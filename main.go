package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
)

func main() {
	var err error

	var argHelp string = "Please run following command: go run main -key=\"encryption key\" -encrypt=\"a string you want to encrypt\""

	encryptArg := flag.String("encrypt", "", argHelp)
	keyArg := flag.String("key", "", argHelp)
	flag.Parse()

	encryptText := *encryptArg
	keyText := *keyArg

	if encryptText == "" || keyText == "" {
		fmt.Println(argHelp)
		return
	}

	encryptedText, err := encrypt(encryptText, keyText)
	if err != nil {
		panic(err)
	}
	fmt.Println(encryptedText)

	decryptedText, err := decrypt(encryptedText, keyText)
	if err != nil {
		panic(err)
	}
	fmt.Println(decryptedText)
}

func encrypt(stringToEncrypt string, keyString string) (string, error) {
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return "", err
	}

	plainByte := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encryptedByte := aesGCM.Seal(nonce, nonce, plainByte, nil)
	return fmt.Sprintf("%x", encryptedByte), nil
}

func decrypt(encryptedString string, keyString string) (string, error) {
	var plainString string

	key, err := hex.DecodeString(keyString)
	if err != nil {
		return "", err
	}

	enc, err := hex.DecodeString(encryptedString)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plainByte, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	plainString = string(plainByte)
	return plainString, nil
}
