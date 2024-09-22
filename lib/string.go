package lib

import (
	"bytes"
	"math/rand"
	"time"
)

// base64Chars contains all valid base64 characters.
const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// EnsureBase64 checks if all characters in a string are base64 and replaces non-base64 characters with random base64 characters.
func EnsureBase64(input string) string {
	var buffer bytes.Buffer
	rand.New(rand.NewSource(time.Now().UnixNano())) // Seed random number generator

	for _, char := range input {
		if isBase64Char(char) {
			buffer.WriteRune(char)
		} else {
			randomBase64Char := base64Chars[rand.Intn(len(base64Chars))]
			buffer.WriteByte(randomBase64Char)
		}
	}

	return buffer.String()
}

// isBase64Char checks if a character is a valid base64 character.
func isBase64Char(char rune) bool {
	return ('A' <= char && char <= 'Z') ||
		('a' <= char && char <= 'z') ||
		('0' <= char && char <= '9') ||
		char == '+' || char == '/'
}
