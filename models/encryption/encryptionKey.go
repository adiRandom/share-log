package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"shareLog/models/userGrant"
)

type Key struct {
	gorm.Model
	UserID     *uint
	PublicKey  *PublicKey
	PrivateKey *PrivateKey `gorm:"embedded;embeddedPrefix:pk_"`
	UserGrant  userGrant.Type
}

func NewPrivateKey(encryptedHex string, iv string, t userGrant.Type) Key {
	return Key{
		PublicKey:  nil,
		PrivateKey: &PrivateKey{EncryptedHex: encryptedHex, Iv: iv},
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

func NewEncryptionKey(pubKey *eciesgo.PublicKey, pkEncryptedHex string, pkIv string, t userGrant.Type) Key {
	return Key{
		PublicKey:  &PublicKey{pubKey},
		PrivateKey: &PrivateKey{EncryptedHex: pkEncryptedHex, Iv: pkIv},
		UserGrant:  t,
	}
}
