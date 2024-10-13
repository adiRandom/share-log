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
	LogId         *uint
	// The salt used to symmetrically encrypt the underlying ecdsa key if it doesn't belong to a user
	// If it belongs to the user, the key will be encrypted with the user's specific symmetric key which has a constant salt
	Salt       string
	PublicKey  *PublicKey
	PrivateKey *PrivateKey `gorm:"embedded;embeddedPrefix:pk_"`
	UserGrant  userGrant.Type
}

func NewEncryptionKey(pubKey *eciesgo.PublicKey, pkEncryptedHex string, pkIv string, t userGrant.Type, salt string) Key {
	return Key{
		PublicKey:  &PublicKey{pubKey},
		PrivateKey: &PrivateKey{EncryptedHex: pkEncryptedHex, Iv: pkIv},
		UserGrant:  t,
		Salt:       salt,
	}
}
