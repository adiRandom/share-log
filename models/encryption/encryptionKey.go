package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"shareLog/models/userGrant"
)

type Key struct {
	gorm.Model
	OwnerId      uint
	PublicKey    *PublicKey
	PrivateKey   *PrivateKey   `gorm:"embedded;embeddedPrefix:pk_"`
	SymmetricKey *SymmetricKey `gorm:"embedded;embeddedPrefix:symKey_"`
	UserGrant    userGrant.Type
}

func NewEncryptionKey(pubKey *eciesgo.PublicKey, pkEncryptedHex string, pkIv string, t userGrant.Type) Key {
	return Key{
		PublicKey:    &PublicKey{pubKey},
		PrivateKey:   &PrivateKey{EncryptedHex: pkEncryptedHex, Iv: pkIv},
		UserGrant:    t,
		SymmetricKey: nil,
	}
}

func NewSymmetricKey(key string) Key {
	return Key{
		PublicKey:  nil,
		PrivateKey: nil,
		SymmetricKey: &SymmetricKey{
			encryptedString: nil,
			decryptedString: &key,
		},
		UserGrant: userGrant.TYPE_SYMMETRIC,
	}
}
