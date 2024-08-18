package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const aesKeyLength = 32 // bytes

/*
*
@returns cypher text, iv, err
*/
func PerformSymmetricEncryption(data string, key []byte) (string, string, error) {
	paddedKeyBytes := Pad(key, aesKeyLength)
	// Create a new cipher block
	block, err := aes.NewCipher(paddedKeyBytes)
	if err != nil {
		return "", "", err
	}

	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return "", "", err
	}

	// Pad the data to the block size
	paddedData := Pad([]byte(data), block.BlockSize())
	// Create a new cipher
	cipherText := make([]byte, len(paddedData))
	// Create a new CBC encrypter
	encrypter := cipher.NewCBCEncrypter(block, iv)
	// Encrypt the data
	encrypter.CryptBlocks(cipherText, paddedData)
	// Return the encrypted data
	return string(cipherText), string(iv), nil
}

func PerformSymmetricDecryption(cipherText string, plainTextLen int, iv string, key []byte) (string, error) {
	// Convert the key to a byte array
	paddedKeyBytes := Pad(key, aesKeyLength)
	// Create a new cipher block
	block, err := aes.NewCipher(paddedKeyBytes)
	if err != nil {
		return "", err
	}

	decrypter := cipher.NewCBCDecrypter(block, []byte(iv))
	paddedPlainText := make([]byte, len(cipherText))
	// Decrypt the data
	decrypter.CryptBlocks(paddedPlainText, []byte(cipherText))
	plainText := Unpad(paddedPlainText, plainTextLen)
	// Return the encrypted data
	return string(plainText), nil
}

// Function to pad plaintext to the block size
func Pad(src []byte, blockSize int) []byte {
	if len(src) == blockSize {
		return src
	}

	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func Unpad(src []byte, unpaddedLength int) []byte {
	if len(src) == unpaddedLength {
		return src
	}

	padding := len(src) - unpaddedLength
	return src[:len(src)-padding]
}
