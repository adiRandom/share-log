package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"shareLog/models/userGrant"
)

type Key struct {
	gorm.Model
	PublicKey  *PublicKey
	PrivateKey *PrivateKey
	UserGrant  userGrant.Type
}

func NewPrivateKey(encryptedHex string, t userGrant.Type) Key {
	return Key{
		PublicKey:  nil,
		PrivateKey: &PrivateKey{encryptedHex: encryptedHex},
		UserGrant:  t,
	}
}

func NewPublicKey(key *eciesgo.PublicKey, t userGrant.Type) Key {
	return Key{
		PublicKey:  &PublicKey{key},
		PrivateKey: nil,
		UserGrant:  t,
	}
}
