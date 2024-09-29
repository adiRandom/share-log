package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"shareLog/models/userGrant"
)

type Key struct {
	gorm.Model
	UserOwnerId   *uint
	InviteOwnerId *uint
	PublicKey     *PublicKey
	PrivateKey    *PrivateKey `gorm:"embedded;embeddedPrefix:pk_"`
	UserGrant     userGrant.Type
}

func NewEncryptionKey(pubKey *eciesgo.PublicKey, pkEncryptedHex string, pkIv string, t userGrant.Type) Key {
	return Key{
		PublicKey:  &PublicKey{pubKey},
		PrivateKey: &PrivateKey{EncryptedHex: pkEncryptedHex, Iv: pkIv},
		UserGrant:  t,
	}
}
