package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
)

type EncryptionKey struct {
	gorm.Model
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

func NewEncryptionKey(key eciesgo.PrivateKey) EncryptionKey {
	return EncryptionKey{
		PublicKey:  PublicKey{key.PublicKey},
		PrivateKey: PrivateKey{hex: key.Hex()},
	}
}
