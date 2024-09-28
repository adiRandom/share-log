package lib

import (
	"bytes"
	"math/rand"
	"time"
)

// base64Chars contains all valid base64 characters.
const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func GetRandomString(length int) string {
	var buffer bytes.Buffer
	rand.New(rand.NewSource(time.Now().UnixNano())) // Seed random number generator

	for i := 0; i < length; i++ {
		randomBase64Char := base64Chars[rand.Intn(len(base64Chars))]
		buffer.WriteByte(randomBase64Char)
	}

	return buffer.String()
}
