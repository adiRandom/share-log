package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"shareLog/models/encryption/keyType"
)

type Key struct {
	gorm.Model
	PublicKey  *PublicKey
	PrivateKey *PrivateKey
	Type       keyType.Type
}

func NewPrivateKey(key *eciesgo.PrivateKey, t keyType.Type) Key {
	return Key{
		PublicKey:  nil,
		PrivateKey: &PrivateKey{encryptedHex: key.Hex()},
		Type:       t,
	}
}

func NewPublicKey(key *eciesgo.PublicKey, t keyType.Type) Key {
	return Key{
		PublicKey:  &PublicKey{key},
		PrivateKey: nil,
		Type:       t,
	}
}
