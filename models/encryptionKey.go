package models

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
)

type EncryptionKey struct {
	gorm.Model
	PublicKeyHex           string
	EncryptedPrivateKeyHex string
}

func NewEncryptionKey(key eciesgo.PrivateKey) EncryptionKey {
	return EncryptionKey{
		PublicKeyHex:           key.PublicKey.Hex(false),
		EncryptedPrivateKeyHex: key.Hex(),
	}
}
