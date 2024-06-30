package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
)

type EncryptionKey struct {
	gorm.Model
	PublicKey  PublicKey
	PrivateKey *PrivateKey
	Type       string
}

const CLIENT_TYPE = "client"
const OWNER_TYPE = "owner"
const OWNER_PUBLIC_KEY = "ownerPublicKey"

func NewEncryptionKey(key eciesgo.PrivateKey, keyType string) EncryptionKey {
	return EncryptionKey{
		PublicKey:  PublicKey{key.PublicKey},
		PrivateKey: &PrivateKey{encryptedHex: key.Hex()},
		Type:       keyType,
	}
}
